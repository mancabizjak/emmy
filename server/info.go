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
	"golang.org/x/net/context"

	"github.com/xlab-si/emmy/config"
	pb "github.com/xlab-si/emmy/protobuf"
)

func (s *Server) GetServiceInfo(ctx context.Context, message *pb.EmptyMsg) (*pb.ServiceInfo, error) {
	s.Logger.Info("Client requested service information")

	name, provider, description := config.LoadServiceInfo()
	info := &pb.ServiceInfo{
		Name:        name,
		Provider:    provider,
		Description: description,
	}

	return info, nil
}
