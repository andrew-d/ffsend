package main

import (
	"github.com/spf13/cobra"
)

var mainCmd = &cobra.Command{
	Use:   "ffsend",
	Short: "ffsend is a command-line file transfer utility",
}

func init() {
}

func main() {
	mainCmd.AddCommand(serverCmd)
	mainCmd.AddCommand(clientCmd)
	mainCmd.AddCommand(generateCmd)
	//mainCmd.AddCommand(bounceCmd)
	mainCmd.Execute()
}

//func runBounce(cmd *cobra.Command, args []string)   {}
