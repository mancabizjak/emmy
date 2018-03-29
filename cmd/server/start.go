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
	"github.com/xlab-si/emmy/log"
	"github.com/xlab-si/emmy/server"
)

// startEmmyServer configures and starts the gRPC server at the desired port
func startEmmyServer(port int, certPath, keyPath, dbAddress, logFilePath,
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

	srv, err := server.NewServer(certPath, keyPath, dbAddress, logger, configFile)
	if err != nil {
		return err
	}

	srv.EnableTracing()
	return srv.Start(port)
}
