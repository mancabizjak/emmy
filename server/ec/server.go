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

package ec

import (
	"fmt"

	"github.com/xlab-si/emmy/crypto/groups"
	pb "github.com/xlab-si/emmy/protobuf"
	"github.com/xlab-si/emmy/server"
)

type ECArithmeticServer interface {
	pb.Protocol_ECServer
	pb.PseudonymSystem_ECServer
	pb.PseudonymSystemCA_ECServer
}

// Server struct implements the ECArithmeticServer interface.
var _ ECArithmeticServer = (*Server)(nil)

type Server struct {
	*server.Server
	curve groups.ECurve // Curve to be used in all schemes.
}

func NewServer(curve groups.ECurve, server *server.Server) *Server {
	s := &Server{
		Server: server,
		curve:  curve,
	}
	s.RegisterServices()

	return s
}

// registerServices binds gRPC server interfaces to the server instance itself, as the server
// provides implementations of these interfaces.
func (s *Server) RegisterServices() {
	pb.RegisterProtocol_ECServer(s.GrpcServer, s)
	pb.RegisterPseudonymSystem_ECServer(s.GrpcServer, s)
	pb.RegisterPseudonymSystemCA_ECServer(s.GrpcServer, s)

	s.Logger.Notice("Registered gRPC Services")
}

func (s *Server) Run(stream pb.Protocol_EC_RunServer) error {
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
	case pb.SchemaType_PEDERSEN_EC:
		err = s.Pedersen(s.curve, stream)
	case pb.SchemaType_SCHNORR_EC:
		err = s.Schnorr(req, protocolType, stream, s.curve)
	}

	if err != nil {
		s.Logger.Error("Closing RPC due to previous errors")
		return fmt.Errorf("RPC call failed: %v", err)
	}

	s.Logger.Notice("RPC finished successfully")
	return nil
}
