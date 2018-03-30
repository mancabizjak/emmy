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
	"path/filepath"

	"fmt"
	"os"
	"strings"

	"github.com/urfave/cli"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/log"
	"github.com/xlab-si/emmy/server"
	"github.com/xlab-si/emmy/server/psys"
)

const (
	emmyDirName    = ".emmy"
	emmyConfigFile = "emmy.conf"
)

var Cmd = cli.Command{
	Name:  "server",
	Usage: "A server (verifier) that verifies clients (provers)",
	Subcommands: []cli.Command{
		{
			Name:  "start",
			Usage: "Starts emmy server",
			Flags: startFlags,
			Action: func(ctx *cli.Context) error {
				err := Start(
					ctx.Int("port"),
					ctx.String("cert"),
					ctx.String("key"),
					ctx.String("db"),
					ctx.String("logfile"),
					ctx.String("loglevel"),
					fmt.Sprintf("%s/.emmy/emmy.psys", ctx.String("d")))
				if err != nil {
					return cli.NewExitError(err, 1)
				}
				return nil
			},
		},
		{
			Name:  "bootstrap",
			Usage: "Bootstraps emmy server before first use",
			Flags: []cli.Flag{emmyDirFlag},
			Action: func(ctx *cli.Context) error {
				emmyDirPath := fmt.Sprintf("%s/.emmy", ctx.String("d"))
				return Bootstrap(emmyDirPath)
			},
		},
		{
			Name:  "reconfigure",
			Usage: "Reconfigures already configured emmy server",
		},
		{
			Name:  "clean",
			Usage: "Removes directory with emmy server configuration",
			Flags: []cli.Flag{emmyDirFlag,
				cli.BoolFlag{
					Name:  "noninteractive",
					Usage: "don't prompt before removing emmy server configuration",
				},
			},
			Action: func(ctx *cli.Context) error {
				emmyDirPath := fmt.Sprintf("%s/.emmy", ctx.String("d"))
				return Clean(emmyDirPath, ctx.Bool("noninteractive"))
			},
		},
	},
}

var emmyDirFlag = cli.StringFlag{
	Name:  "dir, d",
	Value: os.Getenv("HOME"),
	Usage: "`PATH` where emmy server configuration directory will be created",
}

// startFlags are the flags used by the server CLI commands.
var startFlags = []cli.Flag{
	// portFlag indicates the port where emmy server will listen.
	cli.IntFlag{
		Name:  "port, p",
		Value: config.LoadServerPort(),
		Usage: "`PORT` where emmy server will listen for client connections",
	},
	// certFlag keeps the path to server's certificate in PEM format
	// (for establishing a secure channel with the server).
	cli.StringFlag{
		Name:  "cert",
		Value: filepath.Join(config.LoadTestdataDir(), "server.pem"),
		Usage: "`PATH` to servers certificate file",
	},
	// keyFlag keeps the path to server's private key in PEM format
	// (for establishing a secure channel with the server).
	cli.StringFlag{
		Name:  "key",
		Value: filepath.Join(config.LoadTestdataDir(), "server.key"),
		Usage: "`PATH` to server key file",
	},
	// dbEndpointFlag points to the endpoint at which emmy server will contact redis database.
	cli.StringFlag{
		Name:  "db",
		Value: config.LoadRegistrationDBAddress(),
		Usage: "`URI` of redis database to hold registration keys, in the form redisHost:redisPort",
	},
	// logFilePathFlag indicates a path to the log file used by the server (optional).
	cli.StringFlag{
		Name:  "logfile",
		Value: "",
		Usage: "`PATH` to the file where server logs will be written (created if it doesn't exist)",
	},
	// logLevelFlag indicates the log level applied to client/server loggers.
	cli.StringFlag{
		Name:  "loglevel, l",
		Value: "info",
		Usage: "debug|info|notice|error|critical",
	},
	emmyDirFlag,
}

// Bootstrap generates and stores server configuration.
// This is required before running the server for the first time, so that all
// crypto parameters are freshly generated.
func Bootstrap(dir string) error {
	if _, err := os.Stat(dir); err == nil {
		msg := fmt.Sprintf("emmy directory %s already exists", dir)
		return cli.NewExitError(msg, 1)
	}
	if err := os.Mkdir(dir, 0744); err != nil { // 0644 - permission denied!
		return cli.NewExitError(err.Error(), 1) // system error
	}

	//generator := &config.PseudonymSystem{}
	//psysconfig := generator.Generate()
	psysconfig := psys.NewConfig()

	// read mode, generate as appropriate

	if err := config.Store(dir+"/emmy.psys", psysconfig); err != nil {
		return cli.NewExitError(err.Error(), 1)
	}

	return nil
}

func Clean(dir string, promptUser bool) error {
	if !strings.Contains(dir, emmyDirName) { // check that we were not passed an arbitrary directory
		msg := fmt.Sprintf("skipping deletion of %s - not an emmy directory", dir)
		return cli.NewExitError(msg, 1)
	}

	if _, err := os.Stat(dir); err != nil { // directory does not exist
		return nil
	}

	if promptUser {
		fmt.Print("are you sure [y/n]? If you proceed, all your server" +
			" configuration and cryptographic material will be lost > ")
		var in string
		if _, err := fmt.Scanln(&in); err != nil {
			return cli.NewExitError(err.Error(), 1) // error reading input
		}

		if strings.ToLower(in) != "y" { // user didn't type 'y', abort
			return nil
		}
	}

	if err := os.RemoveAll(dir); err != nil { // error removing emmy dir
		return cli.NewExitError(err.Error(), 1)
	}

	fmt.Println("emmy server configuration erased. " +
		"Run 'emmy server bootstrap' to regenerate it.")
	return nil
}

// Start configures and starts the gRPC server at the desired port
func Start(port int, certPath, keyPath, dbAddress, logFilePath,
	logLevel, configFile string) error {
	var err error
	var logger log.Logger

	if logFilePath == "" {
		logger, err = log.NewStdoutLogger("server", logLevel, log.FORMAT_LONG)
	} else {
		logger, err = log.NewStdoutFileLogger("server", logFilePath, logLevel, log.FORMAT_LONG,
			log.FORMAT_LONG_COLORLESS)
	}
	if err != nil {
		return err
	}

	srv, err := server.NewGrpcServer(certPath, keyPath, logger)
	if err != nil {
		return err
	}

	srv.EnableTracing()
	return srv.Start(port)
}
