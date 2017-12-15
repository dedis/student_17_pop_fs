package main

import (
	"dagapython"
	"fmt"
	"os"

	"gopkg.in/dedis/crypto.v0/abstract"
)

func main() {
	os.Exit(mainExitCode())
}

func mainExitCode() int {
	//Number of clients
	c := 20
	//Number of servers
	s := 10

	//Generates clients
	var X []abstract.Point
	var clients []dagapython.Client
	for i := 0; i < c; i++ {
		client, err := dagapython.CreateClient(i, nil)
		if err != nil {
			fmt.Printf("Cannot create clients:\n%s\n", err)
			return 1
		}
		clients = append(clients, client)
		X = append(X, client.GetPublicKey())
	}

	//Generates servers
	var Y []abstract.Point
	var servers []dagapython.Server
	for j := 0; j < s; j++ {
		server, err := dagapython.CreateServer(j, nil)
		if err != nil {
			fmt.Printf("Cannot create servers:\n%s\n", err)
			return 1
		}
		servers = append(servers, server)
		Y = append(Y, server.GetPublicKey())
	}

	return 0
}
