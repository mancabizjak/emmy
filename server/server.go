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
	"io"
	"math"
	"net"

	"net/http"

	"github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/xlab-si/emmy/log"
	pb "github.com/xlab-si/emmy/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type AnonymousAuthServerConfigurator interface {
	GenerateCryptoConfig() interface{}
}

// EmmyServer is an interface composed of all the auto-generated server interfaces that
// declare gRPC handler functions for emmy protocols and schemes.
/*type EmmyServer interface {
	pb.PseudonymSystemServer
	pb.PseudonymSystemCAServer
	pb.InfoServer
}

// GrpcServer struct implements the EmmyServer interface.
var _ EmmyServer = (*GrpcServer)(nil)
*/

// AnonymousAuthServer represents the core of anonymous authentication server.
// It embeds structs to which  all anonymous, regardless of specific implementations.
// Concrete manifestations of authentication servers, e.g. servers dedicated to specific
// schemes should embed this struct.
type AnonymousAuthServer struct {
	*GrpcServer
	*SessionManager
	*RegistrationManager
}

type GrpcServer struct {
	*grpc.Server
	Logger log.Logger
}

// NewServer initializes an instance of the GrpcServer struct and returns a pointer.
// It performs some default configuration (tracing of gRPC communication and interceptors)
// and registers RPC server handlers with gRPC server. It requires TLS cert and keyfile
// in order to establish a secure channel with clients.
func NewGrpcServer(certFile, keyFile string, logger log.Logger) (*GrpcServer, error) {
	logger.Info("Instantiating new server")

	// Obtain TLS credentials
	creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	logger.Infof("Successfully read certificate [%s] and key [%s]", certFile, keyFile)

	// Allow as much concurrent streams as possible and register a gRPC stream interceptor
	// for logging and monitoring purposes.
	server := &GrpcServer{
		Server: grpc.NewServer(
			grpc.Creds(creds),
			grpc.MaxConcurrentStreams(math.MaxUint32),
			grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
		),
		Logger: logger,
	}

	// Disable tracing by default, as is used for debugging purposes.
	// The user will be able to turn it on via GrpcServer's EnableTracing function.
	grpc.EnableTracing = false

	// Register our services with the supporting gRPC server
	//server.registerServices()

	// Initialize gRPC metrics offered by Prometheus package
	grpc_prometheus.Register(server.Server)

	return server, nil
}

// Start configures and starts the protocol server at the requested port.
func (s *GrpcServer) Start(port int) error {
	connStr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", connStr)
	if err != nil {
		return fmt.Errorf("could not connect: %v", err)
	}

	// Register Prometheus metrics handler and serve metrics page on the desired endpoint.
	// Metrics are handled via HTTP in a separate goroutine as gRPC requests,
	// as grpc server's performance over HTTP (GrpcServer.ServeHTTP) is much worse.
	http.Handle("/metrics", prometheus.Handler())

	// After this, /metrics will be available, along with /debug/requests, /debug/events in
	// case server's EnableTracing function is called.
	go http.ListenAndServe(":8881", nil)

	// From here on, gRPC server will accept connections
	s.Logger.Noticef("Emmy server listening for connections on port %d", port)
	return s.Serve(listener)
}

// Teardown stops the protocol server by gracefully stopping enclosed gRPC server.
func (s *GrpcServer) Teardown() {
	s.Logger.Notice("Tearing down gRPC server")
	s.GracefulStop()
}

// EnableTracing instructs the gRPC framework to enable its tracing capability, which
// is mainly used for debugging purposes.
// Although this function does not explicitly affect the GrpcServer struct, it is wired to GrpcServer
// in order to provide a nicer API when setting up the server.
func (s *GrpcServer) EnableTracing() {
	grpc.EnableTracing = true
	s.Logger.Notice("Enabled gRPC tracing")
}

// registerServices binds gRPC server interfaces to the server instance itself, as the server
// provides implementations of these interfaces.
/*func (s *GrpcServer) registerServices() {
	pb.RegisterInfoServer(s)
	//pb.RegisterPseudonymSystemServer(s.GrpcServer, s)
	//pb.RegisterPseudonymSystemCAServer(s.GrpcServer, s)

	s.Logger.Notice("Registered gRPC Services")
}*/

func (s *GrpcServer) Send(msg *pb.Message, stream pb.ServerStream) error {
	if err := stream.Send(msg); err != nil {
		return fmt.Errorf("error sending message: %v", err)
	}

	s.Logger.Infof("Successfully sent response of type %T", msg.Content)
	s.Logger.Debugf("%+v", msg)

	return nil
}

func (s *GrpcServer) Receive(stream pb.ServerStream) (*pb.Message, error) {
	resp, err := stream.Recv()
	if err == io.EOF {
		return nil, err
	} else if err != nil {
		return nil, fmt.Errorf("an error occurred: %v", err)
	}
	s.Logger.Infof("Received request of type %T from the stream", resp.Content)
	s.Logger.Debugf("%+v", resp)

	return resp, nil
}
