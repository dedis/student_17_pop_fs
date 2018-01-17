package daga_test

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"

	"github.com/dedis/student_17_pop_fs/daga"
	"gopkg.in/dedis/crypto.v0/abstract"
)

func TestScenario(test *testing.T) {
	//Number of clients
	c := 20
	//Number of servers
	s := 10

	//Generates clients
	var X []abstract.Point
	var clients []daga.Client
	for i := 0; i < c; i++ {
		client, err := daga.CreateClient(i, nil)
		if err != nil {
			fmt.Printf("Cannot create clients:\n%s\n", err)
			return
		}
		clients = append(clients, client)
		X = append(X, client.GetPublicKey())
	}

	//Generates servers
	var Y []abstract.Point
	var servers []daga.Server
	for j := 0; j < s; j++ {
		server, err := daga.CreateServer(j, nil)
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
		temp, err := daga.GenerateClientGenerator(i, &R)
		if err != nil {
			fmt.Printf("Error in client's geenrators:\n%s\n", err)
			return
		}
		H = append(H, temp)
	}

	serviceContext := daga.ContextEd25519{G: daga.Members{X: X, Y: Y}, R: R, H: H}

	//Simulate the transfer of the context from the service to the client
	//Encoding
	netServiceContext, err := serviceContext.NetEncode()
	if err != nil {
		fmt.Printf("Error in context encoding\n%s\n", err)
		return
	}
	netdata, err := json.Marshal(netServiceContext)
	if err != nil {
		fmt.Printf("Cannot json marshal the context\n%s\n", err)
		return
	}
	//Network transfer
	//Decoding
	var netContext daga.NetContextEd25519
	err = json.Unmarshal(netdata, &netContext)
	if err != nil || &netContext == nil {
		fmt.Printf("Cannot json unmarshal the context\n%s\n", err)
		return
	}
	context, err := netContext.NetDecode()
	if err != nil {
		fmt.Printf("Error in context decoding\n%s\n", err)
		return
	}

	//Client's protocol
	var i = rand.Intn(len(X))
	T0, S, secret, err := clients[i].CreateRequest(context)
	if err != nil {
		fmt.Printf("Error when creating the request:\n%s\n", err)
		return
	}
	t, v, w := clients[i].GenerateProofCommitments(context, T0, secret)

	//Simulate the transfer of the commitments t
	//Encoding
	nett, err := daga.NetEncodePoints(*t)
	if err != nil {
		fmt.Printf("Error when encoding the commitments t\n%s\n", err)
		return
	}
	netdata, err = json.Marshal(nett)
	if err != nil {
		fmt.Printf("Cannot json marshal the commitments t\n%s\n", err)
		return
	}
	//Network transfer
	//Decoding
	var nettServer []daga.NetPoint
	err = json.Unmarshal(netdata, &nettServer)
	if err != nil || &nettServer == nil {
		fmt.Printf("Cannot json unmarshal the commitments t\n%s\n", err)
		return
	}
	tserver, err := daga.NetDecodePoints(nett)
	if err != nil || tserver == nil {
		fmt.Printf("Error in t decoding\n%s\n", err)
		return
	}

	//Server generation of the challenge upon receiving t
	var j = rand.Intn(len(Y)) //Randomly selects the leader

	//The commitments and the openings will be stored in the following array to ease their manipulation
	//They will be transferred on the network according to the protocol below
	var commits []daga.Commitment
	var openings []abstract.Scalar
	//Initialize both arrays
	for num := 0; num < len(context.G.Y); num++ {
		commits = append(commits, daga.Commitment{})
		openings = append(openings, daga.Suite.Scalar().Zero())
	}

	//The leader asks other servers to generates commitments by publishing its own signed commitment
	comlead, openlead, err := servers[j].GenerateCommitment(context)
	if err != nil {
		fmt.Printf("Error when generating the leader commitment at server %d\n%s\n", j, err)
		return
	}

	commits[j] = *comlead
	openings[j] = openlead

	//Simulate transfer of comlead
	sendCom, err := comlead.NetEncode()
	if err != nil {
		fmt.Printf("Error when encoding the commitment of the leader %d\n%s\n", j, err)
		return
	}
	netdata, err = json.Marshal(sendCom)
	if err != nil {
		fmt.Printf("Error when json marshal the commitment of the leader %d\n%s\n", j, err)
		return
	}
	//Network transfer
	var rcvCom daga.NetCommitment
	err = json.Unmarshal(netdata, &rcvCom)
	if err != nil {
		fmt.Printf("Error when json unmarshal the commitment of the leader %d\n%s\n", j, err)
		return
	}
	_, err = rcvCom.NetDecode()
	if err != nil {
		fmt.Printf("Error when decoding the commitment of the leader %d\n%s\n", j, err)
		return
	}

	//Each server generates its commitment and send it to the leader
	for num, server := range servers {
		if num == j {
			continue
		}
		com, open, e := server.GenerateCommitment(context)
		if e != nil {
			fmt.Printf("Error when generating the commitment at server %d\n%s\n", num, e)
			return
		}

		commits[num] = *com
		openings[num] = open

		//Simulate the transfer of the commitment over the network
		sendCom, e := com.NetEncode()
		if e != nil {
			fmt.Printf("Error when encoding the commitment at server %d\n%s\n", num, e)
			return
		}
		netdata, e = json.Marshal(sendCom)
		if e != nil {
			fmt.Printf("Error when json marshal the commitment at server %d\n%s\n", num, e)
			return
		}
		//Network transfer
		var rcvCom daga.NetCommitment
		e = json.Unmarshal(netdata, &rcvCom)
		if e != nil {
			fmt.Printf("Error when json unmarshal the commitment of server %d\n%s\n", num, e)
			return
		}
		_, e = rcvCom.NetDecode()
		if e != nil {
			fmt.Printf("Error when decoding the commitment of server %d\n%s\n", num, e)
			return
		}

	}

	//Once the leader has received all the commitments, it checks that they are of correct form and their signatures are valid
	err = daga.VerifyCommitmentSignature(context, commits)
	if err != nil {
		fmt.Printf("Error when verifying the commitments\n%s\n", err)
		return
	}

	//When the verification is done, the leader asks the servers to reveal their openings by sending its own opening
	//Simulate the transfer of the leader's opening over the network
	sendOpen, err := daga.NetEncodeScalar(openlead)
	if err != nil {
		fmt.Printf("Error when encoding the opening of the leader %d\n", j)
		return
	}
	netdata, err = json.Marshal(sendOpen)
	if err != nil {
		fmt.Printf("Error when json marshal the opening of the leader %d\n", j)
		return
	}
	//Network transfer
	var rcvOpen daga.NetScalar
	err = json.Unmarshal(netdata, &rcvOpen)
	if err != nil {
		fmt.Printf("Error when json unmarshal the opening of the leader %d\n", j)
		return
	}
	_, err = rcvOpen.NetDecode()
	if err != nil {
		fmt.Printf("Error when decoding the opening of the leader %d\n", j)
		return
	}

	//Each server ransfers its opening to the leader
	for num := range servers {
		if num == j {
			continue
		}

		//Simulate the transfer of the opening over the network
		sendOpen, e := daga.NetEncodeScalar(openings[num])
		if e != nil {
			fmt.Printf("Error when encoding the opening at server %d\n%s\n", num, e)
			return
		}
		netdata, e = json.Marshal(sendOpen)
		if e != nil {
			fmt.Printf("Error when json marshal the commitment at server %d\n%s\n", num, e)
			return
		}
		//Network transfer
		var rcvOpen daga.NetScalar
		e = json.Unmarshal(netdata, &rcvOpen)
		if e != nil {
			fmt.Printf("Error when json unmarshal the opening of server %d\n%s\n", num, e)
			return
		}
		//No need to check that this valkue is the same as the one before transfer, this is done in the test of the network functions in daga
		_, e = rcvOpen.NetDecode()
		if e != nil {
			fmt.Printf("Error when decoding the opening of server %d\n%s\n", num, e)
			return
		}
	}

	//After receiving all the openings, server j veerifies them and initializes the challenge structure
	challenge, err := daga.InitializeChallenge(context, commits, openings)
	if err != nil {
		fmt.Printf("Error when initializing the challenge\n%s\n", err)
		return
	}

	//Then it executes CheckUpdateChallenge
	servers[j].CheckUpdateChallenge(context, challenge)

	//Next it sends this message to the next server
	sendChall, err := challenge.NetEncode()
	if err != nil {
		fmt.Printf("Error when encoding the challenge at the leader %d\n%s\n", j, err)
		return
	}
	netdata, err = json.Marshal(sendChall)
	if err != nil {
		fmt.Printf("Error when json marshal the challenge at leader %d\n%s\n", j, err)
		return
	}
	//Network transfer

	//Each server receives the message
	//then executes CheckUpdateChallenge
	//and finally pass the challenge to the next one until it reaches the leader again
	for shift := 1; shift <= len(context.G.Y); shift++ {
		index := (j + shift) % (len(context.G.Y))
		//Receive the previous message
		var rcvChall daga.NetChallengeCheck
		e := json.Unmarshal(netdata, &rcvChall)
		if e != nil {
			fmt.Printf("Error when json unmarshal the challenge at server %d\n%s\n", index, e)
			return
		}
		serverChallenge, e := rcvChall.NetDecode()
		if e != nil {
			fmt.Printf("Error when decoding the challenge at server %d\n%s\n", index, e)
			return
		}

		//Executes CheckUpdateChallenge
		servers[index].CheckUpdateChallenge(context, serverChallenge)

		//Encode and transfer the challenge to the next server
		sendservChall, e := serverChallenge.NetEncode()
		if e != nil {
			fmt.Printf("Error when encoding the challenge at server %d\n%s\n", index, e)
			return
		}
		netdata, e = json.Marshal(sendservChall)
		if e != nil {
			fmt.Printf("Error when json marshal the challenge at server %d\n%s\n", index, e)
			return
		}
		//Network transfer
	}

	//Finally the challenge is back at the leader
	var rcvfinalChall daga.NetChallengeCheck
	err = json.Unmarshal(netdata, &rcvfinalChall)
	if err != nil {
		fmt.Printf("Error when json unmarshal the challenge back at the leader %d\n%s\n", j, err)
		return
	}
	finalChallenge, err := rcvfinalChall.NetDecode()
	if err != nil {
		fmt.Printf("Error when decoding the challenge at the leader %d\n%s\n", j, err)
		return
	}

	//It executes CheckUpdateChallenge to verify the correctness of the challenge
	servers[j].CheckUpdateChallenge(context, finalChallenge)

	//Finalize the challenge before sending it to the client
	clientChallenge, err := daga.FinalizeChallenge(context, finalChallenge)
	if err != nil {
		fmt.Printf("Cannot finalize the challenge\n%s\n", err)
	}

	//The challenge is then sent back to the client
	sendclientChall, err := clientChallenge.NetEncode()
	if err != nil {
		fmt.Printf("Error when encoding the client challenge at the leader %d\n%s\n", j, err)
		return
	}
	netdata, err = json.Marshal(sendclientChall)
	if err != nil {
		fmt.Printf("Error when json marshal the client challenge at leader %d\n%s\n", j, err)
		return
	}
	//Network transfer
	var rcvclientChall daga.NetChallenge
	err = json.Unmarshal(netdata, &rcvclientChall)
	if err != nil {
		fmt.Printf("Error when json unmarshal the challenge at client %d\n%s\n", i, err)
		return
	}
	_, err = rcvclientChall.NetDecode()
	if err != nil {
		fmt.Printf("Error when decoding the challenge at client %d\n%s\n", i, err)
		return
	}

	//Then it can terminate its proof
	cclient, r, err := clients[i].GenerateProofResponses(context, secret, clientChallenge, v, w)
	if err != nil {
		fmt.Printf("Error in the proof responses:\n%s\n", err)
		return
	}

	//The client assemble the message
	msg := clients[i].AssembleMessage(context, &S, T0, clientChallenge, t, cclient, r)

	//Arbitrarily select a server to send the message to
	j = rand.Intn(len(Y))

	//Simulate the transfer of the client message to the server
	sendclientMsg, err := msg.NetEncode()
	if err != nil {
		fmt.Printf("Error when encoding the client message\n%s\n", err)
		return
	}
	netdata, err = json.Marshal(sendclientMsg)
	if err != nil {
		fmt.Printf("Error when json marshal the client message\n%s\n", err)
		return
	}
	//Network transfer
	var rcvclientMsg daga.NetClientMessage
	err = json.Unmarshal(netdata, &rcvclientMsg)
	if err != nil {
		fmt.Printf("Error when json unmarshal the client message\n%s\n", err)
		return
	}
	_, err = rcvclientMsg.NetDecode()
	if err != nil {
		fmt.Printf("Error when decoding the client message\n%s\n", err)
		return
	}

	//This server initialize the server message with the request from the client
	msgServ := servers[j].InitializeServerMessage(msg)

	for shift := range servers {
		index := (j + shift) % len(Y)
		e := servers[index].ServerProtocol(context, msgServ)
		if e != nil {
			fmt.Printf("Error in the server protocol at server %d, shift %d:\n%s\n", (j+shift)%len(Y), shift, e)
			return
		}
		//The server pass the massage to the next one
		//If this is the last server, it broadcasts it to all the servers and the client
		sendservMsg, e := msgServ.NetEncode()
		if e != nil {
			fmt.Printf("Error when encoding the server message at server %d\n%s\n", index, e)
			return
		}
		netdata, e = json.Marshal(sendservMsg)
		if e != nil {
			fmt.Printf("Error when json marshal the server message at server %d\n%s\n", index, e)
			return
		}
		//Network transfer
		var rcvservMsg daga.NetServerMessage
		e = json.Unmarshal(netdata, &rcvservMsg)
		if e != nil {
			fmt.Printf("Error when json unmarshal the server message at server %d\n%s\n", index, e)
			return
		}
		_, e = rcvservMsg.NetDecode()
		if e != nil {
			fmt.Printf("Error when decoding the server message at server %d\n%s\n", index, e)
			return
		}
	}

	//Once the message was completed by all the servers,
	//it is sent back to the client.
	//The clients then verifies the signatures then the proofs and gets its final linkage tag for this context
	Tf, err := clients[i].GetFinalLinkageTag(context, msgServ)
	if err != nil {
		fmt.Printf("Cannot verify server message:\n%s", err)
		return
	} else {
		//A Null value means that the authentication is rejected
		if Tf.Equal(daga.Suite.Point().Null()) {
			fmt.Printf("Authentication rejected\n")
			return
		}
	}

	return
}
