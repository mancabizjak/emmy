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

package end2end

import (
	"fmt"
	"os"
	"testing"

	"io/ioutil"

	"github.com/xlab-si/emmy/client"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/log"
	"github.com/xlab-si/emmy/server"
	"google.golang.org/grpc"
)

var (
	testAAserver           *testAnonymousAuthServer
	testGrpcServerEndpoint = "localhost:7008"

	// testGrpcClientConn is re-used for all the test clients
	testGrpcClientConn *grpc.ClientConn
)

// TestMain is run implicitly and only once, before any of the tests defined in this file run.
// It sets up a test gRPC server and establishes connection to the server. This gRPC client
// connection is then re-used in all the tests to reduce overhead.
// Once all the tests run, we close the connection to the server and stop the server.
func TestMain(m *testing.M) {
pb.
	// Configure a custom logger for the client package
	clientLogger, _ := log.NewStdoutLogger("client", log.NOTICE, log.FORMAT_SHORT)
	client.SetLogger(clientLogger)

	//go server.Start(7008)

	// Establish a connection to previously started server
	testCert, err := ioutil.ReadFile("testdata/server.pem")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	testGrpcClientConn, err = client.GetConnection(
		client.NewConnectionConfig(
			testGrpcServerEndpoint,
			"",
			testCert,
			5000))
	if err != nil {
		panic(err)
	}

	// At this point all the tests will actually run
	returnCode := m.Run()

	// Cleanup - close connection, stop the server and exit
	//server.Teardown()
	testGrpcClientConn.Close()
	os.Exit(returnCode)
}

type testAnonymousAuthServer struct {
	*server.AnonymousAuthServer
}

func (s *testAnonymousAuthServer) switchImpl(f func()) {
	s.GrpcServer.Stop()
	f()
	go s.GrpcServer.Start(7008)
}

func newAnonymousAuthServer() *testAnonymousAuthServer {
	// Configure dependencies
	logger, _ := log.NewStdoutLogger("testServer", log.NOTICE, log.FORMAT_LONG)
	grpcServer, err := server.NewGrpcServer(
		"testdata/server.pem",
		"testdata/server.key",
		logger,
	)
	if err != nil {
		panic(err)
	}

	sm, err := server.NewSessionManager(config.LoadSessionKeyMinByteLen())
	if err != nil {
		panic(err)
	}

	rm, err := server.NewRegistrationManager("localhost:6379")
	if err != nil {
		panic(err)
	}

	return &testAnonymousAuthServer{
		GrpcServer:          grpcServer,
		SessionManager:      sm,
		RegistrationManager: rm,
	}

}

// TestInvalidStreamGenerationFunction verifies that if clients using streaming RPCs to
// communicate with the server try to open a client stream with an invalid stream generation
// function, the error gets caught.
/*func TestInvalidStreamGenerationFunction(t *testing.T) {
	// We don't care about which client we instantiate here, or its arguments,
	// since the underlying behavior we're testing is the same for all of them
	c, _ := NewPseudonymsysCAClient(testGrpcClientConn, nil)
	// This is otherwise called implicitly at the beginning of any client's function
	// for running a given cryptographic protocol
	res := c.openStream(c.grpcClient, "InvalidFunc")
	assert.NotNil(t, res, "stream generation function is invalid, error should be produced")
}
*/
