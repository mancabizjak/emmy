// Copyright © 2018 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"os"

	"github.com/emmyzkp/emmy/mock"

	"github.com/emmyzkp/emmy/anauth/cl"

	"github.com/emmyzkp/emmy/anauth"
	"github.com/emmyzkp/emmy/log"

	"github.com/spf13/cobra"
)

var srv *anauth.GrpcServer

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Starts emmy anonymous authentication server",
	Long: `emmy server is a server (verifier) that verifies 
clients (provers).`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// FIXME make everything configurable
		lgr, err := log.NewStdoutLogger("cl", log.DEBUG, log.FORMAT_LONG)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		// FIXME
		srv, err = anauth.NewGrpcServer(
			"anauth/test/testdata/server.pem",
			"anauth/test/testdata/server.key",
			lgr,
		)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		srv.Start(7007) // FIXME
	},
}

var serverCLCmd = &cobra.Command{
	Use: "cl",
	Short: "Configures the server to run Camenisch-Lysyanskaya scheme for" +
		" anonymous authentication.",
	Run: func(cmd *cobra.Command, args []string) {
		/*sk := &cl.SecKey{}
		pk := &cl.PubKey{}
		err := cl.ReadGob("anauth/test/testdata/clSecKey.gob", sk)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		err = cl.ReadGob("anauth/test/testdata/clPubKey.gob", pk)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}*/
		// FIXME this is to match with the client.
		//  We then announce the pubkey via a RPC service
		keys, _ := cl.GenerateKeyPair(cl.GetDefaultParamSizes())
		// TODO STORE SECRET AND PUBLIC KEYS UPON GENERATION!
		clService, _ := cl.NewServer(
			cl.NewMockRecordManager(),
			&cl.KeyPair{
				Sec: keys.Sec,
				Pub: keys.Pub,
			})

		mockDb := &mock.RegKeyDB{} // TODO fixme
		mockDb.Insert("abc")
		clService.RegMgr = mockDb
		clService.SessMgr, _ = anauth.NewRandSessionKeyGen(32)

		srv.RegisterService(clService)
	},
}

var serverPsysCmd = &cobra.Command{
	Use: "psys",
	Short: "Configures the server to run pseudonym system scheme for" +
		" anonymous authentication. Uses modular arithmetic.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("running psys server")
	},
}

var serverECPsysCmd = &cobra.Command{
	Use: "ecpsys",
	Short: "Configures the server to run pseudonym system scheme for" +
		" anonymous authentication. Uses EC arithmetic.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("running ecpsys server")
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)

	serverCmd.PersistentFlags().IntP("port", "p",
		7007,
		"Port where emmy server will listen for client connections")
	serverCmd.PersistentFlags().StringP("cert", "",
		".",
		"Path to server's certificate file")
	serverCmd.PersistentFlags().StringP("key", "",
		".",
		"Path to server's key file")
	serverCmd.PersistentFlags().StringP("db", "",
		"localhost:6666",
		"URI of redis database to hold registration keys, in the form redisHost:redisPort")
	serverCmd.PersistentFlags().StringP("logfile", "",
		"",
		"Path to the file where server logs will be written ("+
			"created if it doesn't exist)")

	serverCmd.AddCommand(serverCLCmd, serverPsysCmd, serverECPsysCmd)
}
