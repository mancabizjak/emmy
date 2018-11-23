/*
 * Copyright 2017 XLAB d.o.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package server

import (
	"fmt"
	"math"
	"net"
	"net/http"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/emmyzkp/emmy/schemes/cl"
	"github.com/emmyzkp/emmy/schemes/ecpseudsys"
	"github.com/emmyzkp/emmy/schemes/pseudsys"
	"github.com/emmyzkp/emmy/registration"
	"github.com/emmyzkp/emmy/session"
	"github.com/emmyzkp/crypto/ec"
	"github.com/emmyzkp/emmy/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"math/big"
	"github.com/emmyzkp/crypto/schnorr"
)

type GrpcServer struct {
	*grpc.Server
	Logger log.Logger

	creds credentials.TransportCredentials
	service AnonAuthService
}

type AnonAuthService interface {
	Registrable
	Configurable
}

type Configurable interface {
	Configure(...interface{}) error
}

// Registrable registers a grpc service handler to
// a grpc.GrpcServer passed as argument.
type Registrable interface {
	RegisterTo(*grpc.Server)
}

func (s *GrpcServer) RegisterService(r Registrable) error {
	if s.service != nil {
		return fmt.Errorf("anonymous authentication service is" +
			" already registered")
	}
	r.RegisterTo(s.Server)
	return nil
}

func (s *GrpcServer) Use(srvs ...AnonAuthService) {
	for _, srv := range srvs {
		srv.Configure()
		srv.RegisterTo(s.Server)
	}
}


// FIXME
// pass grpc.Server as an argument

// NewGrpcServer initializes an instance of the GrpcServer struct and returns a pointer.
// It performs some default configuration (tracing of gRPC communication and interceptors)
// and registers RPC server handlers with gRPC server. It requires TLS cert and keyfile
// in order to establish a secure channel with clients.
func NewGrpcServer(certFile, keyFile string, regMgr registration.Manager,
	recMgr cl.ReceiverRecordManager, logger log.Logger) (*GrpcServer, error) {
	// TODO check for nil logger?
	logger.Info("Instantiating new server")

	// Obtain TLS credentials
	creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create TLS credentials")
	}

	logger.Infof("Successfully read certificate [%s] and key [%s]", certFile, keyFile)

	// FIXME pass session manager
	// config.LoadSessionKeyMinByteLen()
	/*sessMgr, err := session.NewRandSessionKeyGen(64)
	if err != nil {
		logger.Warning(err)
	}*/

	// Allow as much concurrent streams as possible and register a gRPC stream interceptor
	// for logging and monitoring purposes.
	s := &GrpcServer{
		Server: grpc.NewServer(
			grpc.Creds(creds),
			grpc.MaxConcurrentStreams(math.MaxUint32),
			//grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
			//grpc.StreamInterceptor(),
			// FIXME to remove?
		),
		Logger: logger,
		//sessMgr: sessMgr,
		//regMgr:  regMgr,
	}

	// Disable tracing by default, as is used for debugging purposes.
	// The user will be able to turn it on via GrpcServer's EnableTracing function.
	grpc.EnableTracing = false

	// RegisterTo our services with the supporting gRPC s
	//s.registerCL(recMgr)
	//s.registerPsysCA()
	//s.registerPsysOrg(regMgr, sessMgr)

	//s.registerEcpsysCA()
	//s.registerEcpsysOrg(regMgr, sessMgr)
	logger.Notice("Registered gRPC Services")

	// Initialize gRPC metrics offered by Prometheus package
	//grpc_prometheus.RegisterTo(s.GrpcServer)

	return s, nil
}

// Start configures and starts the protocol server at the requested port.
func (s *GrpcServer) Start(port int) error {
	connStr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", connStr)
	if err != nil {
		return fmt.Errorf("could not connect: %v", err)
	}

	// RegisterTo Prometheus metrics handler and serve metrics page on the desired endpoint.
	// Metrics are handled via HTTP in a separate goroutine as gRPC requests,
	// as grpc server's performance over HTTP (GrpcServer.ServeHTTP) is much worse.
	http.Handle("/metrics", prometheus.Handler())

	// After this, /metrics will be available, along with /debug/requests, /debug/events in
	// case server's EnableTracing function is called.
	go http.ListenAndServe(":8881", nil)

	// From here on, gRPC server will accept connections
	s.Logger.Noticef("Emmy server listening for connections on port %d", port)
	s.Server.Serve(listener)
	return nil
}

// Teardown stops the protocol server by gracefully stopping enclosed gRPC server.
func (s *GrpcServer) Teardown() {
	s.Logger.Notice("Tearing down gRPC server")
	s.Server.GracefulStop()
}

// EnableTracing instructs the gRPC framework to enable its tracing capability, which
// is mainly used for debugging purposes.
// Although this function does not explicitly affect the GrpcServer struct, it is wired to GrpcServer
// in order to provide a nicer API when setting up the server.
func (s *GrpcServer) EnableTracing() {
	grpc.EnableTracing = true
	s.Logger.Notice("Enabled gRPC tracing")
}

func (s *GrpcServer) RegisterCL(recMgr cl.ReceiverRecordManager) (*cl.PubKey,
	error) {
	//pubKeyPath := "testdata/clPubKey.gob"
	//secKeyPath := "testdata/clSecKey.gob"
	params := cl.GetDefaultParamSizes()
	keys, err := cl.GenerateKeyPair(params)
	if err != nil {
		return nil, err
	}

	srv, err := cl.NewServer(recMgr, keys)
	if err != nil {
		panic(err)
	}
	s.RegisterService(srv)

	return keys.Pub, nil
}

func (s *GrpcServer) registerPsysCA(g *schnorr.Group,
	secKey *big.Int, pubKey *pseudsys.PubKey) {
	srv := pseudsys.NewCAServer(g, secKey, pubKey)
	s.RegisterService(srv)
}

func (s *GrpcServer) registerPsysOrg(regMgr registration.Manager,
	sessionManager session.Manager, g *schnorr.Group,
	orgSecrets *pseudsys.SecKey, orgPubKey *pseudsys.PubKey,
	caPubKey *pseudsys.PubKey) {
	srv := pseudsys.NewOrgServer(g,
		orgSecrets,
		orgPubKey,
		caPubKey,
	)
	// Move to constructor
	srv.RegMgr = regMgr
	srv.SessMgr = sessionManager
	s.RegisterService(srv)
}

func (s *GrpcServer) registerEcpsysCA(caSecKey *big.Int,
	caPubKey *pseudsys.PubKey, curve ec.Curve) {
	srv := ecpseudsys.NewCAServer(
		caSecKey,
		caPubKey,
		curve,
	)
	s.RegisterService(srv)
}

func (s *GrpcServer) registerEcpsysOrg(regMgr registration.Manager,
	sessionManager session.Manager,
	curve ec.Curve, orgSecrets *pseudsys.SecKey,
	orgPubKeys *ecpseudsys.PubKey, caPubKey *pseudsys.PubKey) {
	srv := ecpseudsys.NewOrgServer(
		curve,
		orgSecrets,
		orgPubKeys,
		caPubKey,
	)
	// Move to constructor
	srv.RegMgr = regMgr
	srv.SessMgr = sessionManager
	s.RegisterService(srv)
}
