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

	"github.com/spf13/cobra"
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Starts emmy anonymous authentication server",
	Long: `emmy server is a server (verifier) that verifies 
clients (provers).`,
}

var serverCLCmd = &cobra.Command{
	Use: "cl",
	Short: "Configures emmy server to run Camenisch-Lysyanskaya scheme for" +
		" anonymous authentication",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("running CL server")
	},
}

var serverPsysCmd = &cobra.Command{
	Use: "psys",
	Short: "Configures emmy server to run pseudonym system scheme for" +
		" anonymous authentication. Uses modular arithmetic",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("running psys server")
	},
}

var serverECPsysCmd = &cobra.Command{
	Use: "ecpsys",
	Short: "Configures emmy server to run pseudonym system scheme for" +
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
		"Path to the file where server logs will be written (" +
		"created if it doesn't exist)")

	serverCmd.AddCommand(serverCLCmd, serverPsysCmd, serverECPsysCmd)
}
