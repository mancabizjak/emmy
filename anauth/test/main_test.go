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

package test

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"testing"
	"time"

	"github.com/emmyzkp/emmy/anauth"
	"github.com/emmyzkp/emmy/anauth/cl"
	"github.com/emmyzkp/emmy/log"
	"github.com/emmyzkp/emmy/mock"
	"github.com/go-redis/redis"
	"google.golang.org/grpc"
)

var (
	testAddr = "localhost:7008"
	//testSrv  *testServer
	//testConn *grpc.ClientConn

	recDB    cl.ReceiverRecordManager
	regKeyDB anauth.RegManager
)

var testRedis = flag.Bool(
	"db",
	false,
	"whether to use a real redis server in integration test",
)

// getTestSecureConn establishes a connection to previously started server.
func getTestSecureConn() (*grpc.ClientConn, error) {
	testCert, err := ioutil.ReadFile("testdata/server.pem")
	if err != nil {
		return nil, err
	}
	conn, err := anauth.GetConnection(testAddr,
		anauth.WithCACert(testCert),
		anauth.WithTimeout(500),
	)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func getTestConn() (*grpc.ClientConn, error) {
	//if testConn == nil { // FIXME
	//	fmt.Println("creating fresh conn")
	return grpc.Dial(testAddr,
		grpc.WithInsecure(),
		grpc.WithBlock(),
	)
	//}
	//	return testConn, nil
}

/*
var testEnd2End = flag.Bool(
	"e2e",
	false,
	"whether to run end-to-end tests (requires an instance of emmy server)",
)*/

type testServer struct {
	*grpc.Server
	services []anauth.Service
}

func newTestServer() *testServer {
	grpcSrv := grpc.NewServer()
	return &testServer{grpcSrv, nil}
}

func (s *testServer) addService(as anauth.Service) {
	as.RegisterTo(s.Server)
	fmt.Println("registered service")
}

func (s *testServer) start() {
	lis, err := net.Listen("tcp", testAddr)
	if err != nil {
		panic(err)
	}
	fmt.Println("starting test server")
	s.Server.Serve(lis)
}

func (s *testServer) teardown() {
	fmt.Println("stopping test server")
	s.Server.Stop()
}

// TODO TestMain should determine, based on flags,
// which anonymous authentication services it should test

// TestMain is run implicitly and only once, before any of the tests defined in this file run.
// It sets up a test gRPC server and establishes connection to the server. This gRPC client
// connection is then re-used in all the tests to reduce overhead.
// Once all the tests run, we close the connection to the server and stop the server.
//
// When this package is tested with -db flag, the test will attempt to connect to a redis
// server on localhost:6379.
// In the absence of -db flag, mock implementations will be used.
func TestMain(m *testing.M) {
	flag.Parse()

	testRegKeys := []string{"testRegKey1", "testRegKey2", "testRegKey3", "testRegKey4"}

	//if *testEnd2End {
	if *testRedis { // use real redis instance
		fmt.Println("Using a redis instance for storage")
		// connect to a redis database
		c := redis.NewClient(&redis.Options{
			Addr: "localhost:6379",
		})
		err := c.Ping().Err()
		if err != nil {
			fmt.Println("unable to connect to test redis instance:", err)
			os.Exit(1)
		}

		// insert test registration keys
		for _, regKey := range testRegKeys {
			err = c.Set(regKey, regKey, time.Minute).Err()
			if err != nil {
				fmt.Println("cannot insert test registration keys to redis:", err)
				os.Exit(1)
			}
		}

		regKeyDB = anauth.NewRedisClient(c)
		recDB = cl.NewRedisClient(c)
	} else { // use mock storage
		fmt.Println("Using mock storage")
		// prepare mocks
		db := &mock.RegKeyDB{}
		db.Insert(testRegKeys...)
		regKeyDB = db
		recDB = cl.NewMockRecordManager()
	}

	/*logger, _ := log.NewStdoutLogger("testServer", log.NOTICE,
	log.FORMAT_LONG)

	testSrv, err = server.NewGrpcServer("testdata/server.pem",
		"testdata/server.key", regKeyDB, recDB, logger)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// we need to retrieve public key emitted by this function
	// and capture it in tests
	testSrv.RegisterCL(recDB)*/

	// Configure a custom logger for the client package
	clientLogger, _ := log.NewStdoutLogger("client", log.NOTICE, log.FORMAT_SHORT)
	anauth.SetLogger(clientLogger)

	// At this point all the tests will actually run
	ret := m.Run()

	os.Exit(ret)
}
