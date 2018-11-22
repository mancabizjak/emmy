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
	"os"
	"testing"
	"time"

	"github.com/go-redis/redis"
	"github.com/emmyzkp/anonauth"
	"github.com/emmyzkp/anonauth/schemes/cl"
	"github.com/emmyzkp/anonauth/registration"
	"github.com/emmyzkp/anonauth/log"
	"github.com/emmyzkp/anonauth/mock"
	"google.golang.org/grpc"
	"github.com/xlab-si/emmy"
)

var testAddr = "localhost:7008"
var testSrv *anonauth.GrpcServer

// testConn is re-used for all the test clients
var testConn *grpc.ClientConn

var recDB cl.ReceiverRecordManager
var regKeyDB registration.Manager

var testRedis = flag.Bool(
	"db",
	false,
	"whether to use a real redis server in integration test",
)

// getTestConn establishes a connection to previously started server.
func getTestConn(addr string) (*grpc.ClientConn, error) {
	testCert, err := ioutil.ReadFile("testdata/server.pem")
	if err != nil {
		return nil, err
	}
	conn, err := anonauth.GetConnection(addr,
		anonauth.WithCACert(testCert),
		anonauth.WithTimeout(500),
	)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

/*
var testEnd2End = flag.Bool(
	"e2e",
	false,
	"whether to run end-to-end tests (requires an instance of emmy server)",
)*/

type testRegDb struct {
}

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

	var err error
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

		regKeyDB = registration.NewRedisClient(c)
		recDB = cl.NewRedisClient(c)
	} else { // use mock storage
		fmt.Println("Using mock storage")
		// prepare mocks
		db := &mock.RegKeyDB{}
		db.Insert(testRegKeys...)
		regKeyDB = db
		recDB = cl.NewMockRecordManager()
	}

	logger, _ := log.NewStdoutLogger("testServer", log.NOTICE, log.FORMAT_LONG)
	testSrv, err = anonauth.NewGrpcServer("testdata/server.pem",
		"testdata/server.key",
		regKeyDB, recDB, logger)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Configure a custom logger for the client package
	clientLogger, _ := log.NewStdoutLogger("client", log.NOTICE, log.FORMAT_SHORT)
	emmy.SetLogger(clientLogger)

	go testSrv.Start(7008)

	time.Sleep(time.Second)

	testConn, err = getTestConn(testAddr)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// At this point all the tests will actually run
	ret := m.Run()

	// Cleanup - close connection, stop the server and exit
	testConn.Close()
	testSrv.Teardown()

	os.Exit(ret)
	//}
}
