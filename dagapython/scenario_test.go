package dagapython_test

import (
	"dagapython"
	"fmt"
	"math/rand"
	"testing"

	"gopkg.in/dedis/crypto.v0/abstract"
)

//Allows to exit the program with a message and an error code
func TestScenario(test *testing.T) {
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
			return
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
			return
		}
		servers = append(servers, server)
		Y = append(Y, server.GetPublicKey())
	}

	//Generate server's round secrets
	var R []abstract.Point
	for i := range servers {
		R = append(R, servers[i].GenerateNewRoundSecret())
	}

	//Generate client's generators
	var H []abstract.Point
	for i := 0; i < len(X); i++ {
		temp, err := dagapython.GenerateClientGenerator(i, &R)
		if err != nil {
			fmt.Printf("Error in client's geenrators:\n%s\n", err)
			return
		}
		H = append(H, temp)
	}

	context := dagapython.ContextEd25519{G: dagapython.Members{X: X, Y: Y}, R: R, H: H}

	//Client's protocol
	var i = rand.Intn(len(X))
	T0, S, secret, err := clients[i].CreateRequest(&context)
	if err != nil {
		fmt.Printf("Error when creating the request:\n%s\n", err)
		return
	}
	t, v, w := clients[i].GenerateProofCommitments(&context, T0, secret)

	//Server generation of the challenge upon receiving t
	var j = rand.Intn(len(Y)) //Randomly selects the leader
	//In practice, server j generates its commitments and then send it to the other servers asking them to generate and broadcast their commitments
	//Here, we will just make each server generate its commitment
	var commits []dagapython.Commitment
	var openings []abstract.Scalar
	for _, server := range servers {
		com, open, e := server.GenerateCommitment(&context)
		if e != nil {
			fmt.Printf("Error when generating the commitments:\n%s\n", e)
			return
		}
		commits = append(commits, *com)
		openings = append(openings, open)
	}
	//After receiving all the commitments, a server checks the signatures
	err = dagapython.VerifyCommitmentSignature(&context, &commits)
	if err != nil {
		fmt.Printf("Error in the commitment signature:\n%s\n", err)
		return
	}
	//Then the leader publishes its opening and asked the other servers to do the same
	//Here the openings are already stored in openings
	//Then each server can check that the openings matches
	cs, err := dagapython.CheckOpenings(&context, &commits, &openings)
	if err != nil {
		fmt.Printf("Error in the openings:\n%s\n", err)
	}

	//The leader now creates the challenge and runs CheckUpdateChallenge before passing the message to the next server
	challenge := dagapython.InitializeChallenge(cs)

	for shift := 0; shift < len(Y); shift++ {
		err = servers[(j+shift)%len(Y)].CheckUpdateChallenge(&context, cs, challenge)
		if err != nil {
			fmt.Printf("Error when updating the challenge at server %d:\n%s\n", (j+shift)%len(Y), err)
			return
		}
	}

	//The challenge is then sent back to the client so it can terminates its proof
	cclient, r, err := clients[i].GenerateProofResponses(&context, secret, challenge, v, w)
	if err != nil {
		fmt.Printf("Error in the proof responses:\n%s\n", err)
		return
	}

	//The client assemble the message
	msg := clients[i].AssembleMessage(&context, &S, T0, cs, t, cclient, r)

	//Arbitrarily select a server to send the message to
	j = rand.Intn(len(Y))
	//This server initialize the server message with the request from the client
	msgServ := servers[j].InitializeServerMessage(msg)

	for shift := range servers {
		e := servers[(j+shift)%len(Y)].ServerProtocol(&context, msgServ)
		if e != nil {
			fmt.Printf("Error in the server protocol at server %d, shift %d:\n%s\n", (j+shift)%len(Y), shift, e)
			return
		}
	}

	//Once the message was completed by all the servers,
	//it is sent back to the client.
	//The clients then verifies the signatures then the proofs and gets its final linkage tag for this context
	Tf, err := clients[i].GetFinalLinkageTag(&context, msgServ)
	if err != nil {
		fmt.Printf("Cannot verify server message:\n%s", err)
		return
	} else {
		//A Null value means that the authentication is rejected
		if Tf.Equal(dagapython.Suite.Point().Null()) {
			fmt.Printf("Authentication rejected\n")
			return
		}
	}

	return
}
