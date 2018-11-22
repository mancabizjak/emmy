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

package main

import (
	"fmt"
	"sync"
	"time"

	"io/ioutil"

	"path/filepath"

	"github.com/urfave/cli"
	"github.com/emmyzkp/anonauth/config"
	"github.com/emmyzkp/anonauth/log"
	"google.golang.org/grpc"
	"github.com/emmyzkp/anonauth"
)
/*
// logLevelFlag indicates the log level applied to client/server loggers.
var logLevelFlag = cli.StringFlag{
	Name:  "loglevel, l",
	Value: "info",
	Usage: "debug|info|notice|error|critical",
}*/

var ClientCmd = cli.Command{
	Name:  "client",
	Usage: "A client (prover) that wants to prove something to the server (verifier)",
	// clientFlags are flags common to all client CLI subcommands, regardless of the protocol.
	Flags:       clientFlags,
	Subcommands: clientSubcommands,
}

var clientFlags = []cli.Flag{
	// nClientsFlag indicates the number of (either concurrent or sequential) clients to run.
	cli.IntFlag{
		Name:  "nclients, n",
		Value: 1,
		Usage: "How many clients to run",
	},
	// serverEndpointFlag points to the endpoint at which emmy clients will contact emmy server.
	cli.StringFlag{
		Name:  "server",
		Value: config.LoadServerEndpoint(),
		Usage: "`URI` of emmy server in the form serverHost:serverPort",
	},
	// serverNameOverrideFlag allows the client to skip validation of the server's hostname when
	// checking its CN. Instead, CN from the server's certificate must match the value provided by
	// serverNameOverride flag.
	cli.StringFlag{
		Name:  "servername",
		Value: "",
		Usage: "Name of emmy server for overriding the server name stated in cert's CN",
	},
	// caCertFlag keeps the path to CA's certificate in PEM format
	// (for establishing a secure channel with the server).
	cli.StringFlag{
		Name:  "cacert",
		Value: filepath.Join(config.LoadTestdataDir(), "server.pem"),
		Usage: "`PATH` to certificate file of the CA that issued emmy server's certificate",
	},

	// sysCertPoolFlag indicates whether a client should use system's certificate pool to validate
	// the server's certificate..
	cli.BoolFlag{
		Name:  "syscertpool",
		Usage: "Whether to use host system's certificate pool to validate the server",
	},
	// timeoutFlag indicates the timeout (in seconds) for establishing connection to the server.
	// If connection cannot be established before the timeout, the client fails.
	cli.IntFlag{
		Name:  "timeout, t",
		Value: config.LoadTimeout(),
		Usage: "timeout (in seconds) for establishing connection with the server",
	},
	logLevelFlag,
}

// protocolVariantFlag indicates which protocol variant to demonstrate.
var protocolVariantFlag = cli.StringFlag{
	Name:  "variant, v",
	Value: "sigma",
	Usage: "sigma|zkp|zkpok",
}

// protocolSecretFlag keeps the secret value used to bootstrap a given protocol.
var protocolSecretFlag = cli.Int64Flag{
	Name:  "secret",
	Value: 121212121,
}

// clientSubcommands represent different protocols that can be executed by clients.
var clientSubcommands = []cli.Command{
	{
		Name:     "info",
		Usage:    "Fetch information about the service provider",
		Category: "Info",
		Action: func(ctx *cli.Context) error {
			return run(ctx.Parent(), ctx, func(ctx *cli.Context, conn *grpc.ClientConn) error {
				//_, err := client.GetServiceInfo(conn)
				//return err
				return nil
			})
		},
	},
}

// run accepts pointers to parent (command) and child (subcommand) contexts in order to read
// appropriate command line flags and run a client function either sequentially or concurrently.
// It is supposed to be used as a wrapper around CLI subcommand functions that
// execute client-side of the chosen protocol.
func run(ctx, subCmdCtx *cli.Context, f func(ctx *cli.Context, conn *grpc.ClientConn) error) error {
	var err error
	logger, err := log.NewStdoutLogger("client", ctx.String("loglevel"), log.FORMAT_SHORT)
	if err != nil {
		return cli.NewExitError(err.Error(), 2)
	}
	anonauth.SetLogger(logger)

	// configure how clients will access anonauth server via TLS.
	var connCfg []anonauth.ConnOption
	if !ctx.Bool("syscertpool") {
		caCert, err := ioutil.ReadFile(ctx.String("cacert"))
		if err != nil {
			return cli.NewExitError(err.Error(), 2)
		}

		connCfg = append(connCfg, anonauth.WithCACert(caCert))
	}

	// conn is a connection to emmy server.
	// In case we are running more than one client, conn will be shared among all the clients.
	// We made it global because it is needed in both 'Before' and 'After' actions of the clientCmd.
	var conn *grpc.ClientConn

	if ctx.IsSet("servername") {
		connCfg = append(connCfg, anonauth.WithServerNameOverride(ctx.String("servername")))
	}

	if ctx.IsSet("t") {
		connCfg = append(connCfg, anonauth.WithTimeout(ctx.Int("t")))
	}

	// Establish a connection to emmy server
	conn, err = anonauth.GetConnection(ctx.String("server"), connCfg...)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Cannot connect to gRPC server: %v", err), 2)
	}
	defer conn.Close()

	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < ctx.Int("n"); i++ {
		fmt.Printf("***Running client #%d***\n", i+1)
		if ctx.Bool("concurrent") {
			wg.Add(1)
			go func() {
				err = f(subCmdCtx, conn)
				defer wg.Done()
			}()
		} else {
			err = f(subCmdCtx, conn)
		}
	}
	wg.Wait()
	elapsed := time.Since(start)

	// In case the function 'f' returned an error, signal it to the CLI. It means client
	// is in error.
	if err != nil {
		return cli.NewExitError(err.Error(), 1)
	}

	fmt.Printf("***Time: %v seconds***\n", elapsed.Seconds())
	return nil
}
