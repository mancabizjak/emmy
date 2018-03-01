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

package mod

import (
	"fmt"
	"path/filepath"

	"github.com/xlab-si/emmy/config"
	pb "github.com/xlab-si/emmy/protobuf"
	"github.com/xlab-si/emmy/server"
)

// EmmyServer is an interface composed of all the auto-generated server interfaces that
// declare gRPC handler functions for emmy protocols and schemes.
type ModArithmeticServer interface {
	pb.ProtocolServer
	pb.PseudonymSystemServer
	pb.PseudonymSystemCAServer
}

// Server struct implements the ModArithmeticServer interface.
var _ ModArithmeticServer = (*Server)(nil)

type Server struct {
	*server.Server
}

func NewServer(server *server.Server) *Server {
	s := &Server{
		Server: server,
	}
	s.RegisterServices()

	return s
}

// registerServices binds gRPC server interfaces to the server instance itself, as the server
// provides implementations of these interfaces.
func (s *Server) RegisterServices() {
	pb.RegisterProtocolServer(s.GrpcServer, s)
	pb.RegisterPseudonymSystemServer(s.GrpcServer, s)
	pb.RegisterPseudonymSystemCAServer(s.GrpcServer, s)

	s.Logger.Notice("Registered gRPC Services")
}

func (s *Server) Run(stream pb.Protocol_RunServer) error {
	s.Logger.Info("Starting new RPC")

	req, err := s.Receive(stream)
	if err != nil {
		return err
	}

	reqClientId := req.ClientId
	reqSchemaType := req.Schema
	reqSchemaVariant := req.SchemaVariant

	// Check whether the client requested a valid schema
	reqSchemaTypeStr, schemaValid := pb.SchemaType_name[int32(reqSchemaType)]
	if !schemaValid {
		return fmt.Errorf("client [ %d ] requested invalid schema: %v", reqClientId, reqSchemaType)
	}

	// Check whether the client requested a valid schema variant
	reqSchemaVariantStr, variantValid := pb.SchemaVariant_name[int32(reqSchemaVariant)]
	if !variantValid {
		return fmt.Errorf("client [ %d ] requested invalid schema variant: %v", reqClientId, reqSchemaVariant)
	}

	s.Logger.Noticef("Client [ %v ] requested schema %v, variant %v", reqClientId, reqSchemaTypeStr, reqSchemaVariantStr)

	// Convert Sigma, ZKP or ZKPOK protocol type to a types type
	protocolType := reqSchemaVariant.GetNativeType()

	switch reqSchemaType {

	case pb.SchemaType_PEDERSEN:
		group := config.LoadSchnorrGroup()
		err = s.Pedersen(group, stream)
	case pb.SchemaType_SCHNORR:
		group := config.LoadSchnorrGroup()
		err = s.Schnorr(req, group, protocolType, stream)
	case pb.SchemaType_CSPAILLIER:
		secKeyPath := filepath.Join(config.LoadTestdataDir(), "cspaillierseckey.txt")
		err = s.CSPaillier(req, secKeyPath, stream)
	case pb.SchemaType_QR:
		group := config.LoadSchnorrGroup()
		err = s.QR(req, group, stream)
	case pb.SchemaType_QNR:
		qr := config.LoadQRRSA() // only for testing
		err = s.QNR(req, qr, stream)
	}

	if err != nil {
		s.Logger.Error("Closing RPC due to previous errors")
		return fmt.Errorf("RPC call failed: %v", err)
	}

	s.Logger.Notice("RPC finished successfully")
	return nil
}
