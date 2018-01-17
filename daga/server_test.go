package daga

import (
	"crypto/sha512"
	"io"
	"math/rand"
	"strconv"
	"testing"

	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
)

func TestCreateServer(t *testing.T) {
	//Normal execution
	i := rand.Int()
	s := suite.Scalar().Pick(random.Stream)
	server, err := CreateServer(i, s)
	if err != nil || server.index != i || !server.private.Equal(s) {
		t.Error("Cannot initialize a new server with a given private key")
	}

	server, err = CreateServer(i, nil)
	if err != nil {
		t.Error("Cannot create a new server without a private key")
	}

	//Invalid input
	server, err = CreateServer(-2, s)
	if err == nil {
		t.Error("Wrong check: Invalid index")
	}
}

func TestGetPublicKey_Server(t *testing.T) {
	server, _ := CreateServer(0, suite.Scalar().Pick(random.Stream))
	P := server.GetPublicKey()
	if P == nil {
		t.Error("Cannot get public key")
	}
}

func TestGenerateCommitment(t *testing.T) {
	_, servers, context, _ := generateTestContext(rand.Intn(10)+1, rand.Intn(10)+1)

	//Normal execution
	commit, opening, err := servers[0].GenerateCommitment(context)

	if err != nil {
		t.Error("Cannot generate a commitment")
	}
	if !commit.commit.Equal(suite.Point().Mul(nil, opening)) {
		t.Error("Cannot open the commitment")
	}
	msg, err := commit.commit.MarshalBinary()
	if err != nil {
		t.Error("Invalid commitment")
	}
	err = ECDSAVerify(suite.Point().Mul(nil, servers[0].private), msg, commit.sig.sig)
	if err != nil {
		t.Error("Wrong signature")
	}
}

func TestVerifyCommitmentSignature(t *testing.T) {
	_, servers, context, _ := generateTestContext(rand.Intn(10)+1, rand.Intn(10)+1)

	//Generate commitments
	var commits []Commitment
	for i := 0; i < len(servers); i++ {
		commit, _, _ := servers[i].GenerateCommitment(context)
		commits = append(commits, *commit)
	}

	//Normal execution
	err := VerifyCommitmentSignature(context, commits)
	if err != nil {
		t.Error("Cannot verify the signatures for a legit commit array")
	}

	//Change a random index
	i := rand.Intn(len(servers))
	commits[i].sig.index = i + 1
	err = VerifyCommitmentSignature(context, commits)
	if err == nil {
		t.Errorf("Cannot verify matching indexes for %d", i)
	}
	commits[i].sig.index = i + 1

	//Change a signature
	//Code shown as not covered, but it does detect the modification and returns an error
	sig := commits[i].sig.sig
	sig = append([]byte("A"), sig...)
	sig = sig[:len(commits[i].sig.sig)]
	commits[i].sig.sig = sig
	err = VerifyCommitmentSignature(context, commits)
	if err == nil {
		t.Errorf("Cannot verify signature for %d", i)
	}
}

func TestCheckOpenings(t *testing.T) {
	_, servers, context, _ := generateTestContext(rand.Intn(10)+1, rand.Intn(10)+1)

	//Generate commitments
	var commits []Commitment
	var openings []abstract.Scalar
	for i := 0; i < len(servers); i++ {
		commit, open, _ := servers[i].GenerateCommitment(context)
		commits = append(commits, *commit)
		openings = append(openings, open)
	}

	//Normal execution
	cs, err := CheckOpenings(context, commits, openings)
	if err != nil {
		t.Error("Cannot check the openings")
	}
	challenge := suite.Scalar().Zero()
	for _, temp := range openings {
		challenge = suite.Scalar().Add(challenge, temp)
	}
	if !cs.Equal(challenge) {
		t.Errorf("Wrong computation of challenge cs: %s instead of %s", cs, challenge)
	}

	//Empty inputs
	cs, err = CheckOpenings(nil, commits, openings)
	if err == nil {
		t.Error("Wrong check: Empty context")
	}
	if cs != nil {
		t.Error("cs not nil on empty context")
	}
	cs, err = CheckOpenings(context, nil, openings)
	if err == nil {
		t.Error("Wrong check: Empty commits")
	}
	if cs != nil {
		t.Error("cs not nil on empty commits")
	}
	cs, err = CheckOpenings(context, commits, nil)
	if err == nil {
		t.Error("Wrong check: Empty openings")
	}
	if cs != nil {
		t.Error("cs not nil on empty openings")
	}

	//Change the length of the openings
	CutOpenings := openings[:len(openings)-1]
	cs, err = CheckOpenings(context, commits, CutOpenings)
	if err == nil {
		t.Error("Invalid length check on openings")
	}
	if cs != nil {
		t.Error("cs not nil on opening length error")
	}

	//Change the length of the commits
	CutCommits := commits[:len(commits)-1]
	cs, err = CheckOpenings(context, CutCommits, openings)
	if err == nil {
		t.Error("Invalid length check on comits")
	}
	if cs != nil {
		t.Error("cs not nil on commit length error")
	}

	//Change a random opening
	i := rand.Intn(len(servers))
	openings[i] = suite.Scalar().Zero()
	cs, err = CheckOpenings(context, commits, openings)
	if err == nil {
		t.Error("Invalid opening check")
	}
	if cs != nil {
		t.Error("cs not nil on opening error")
	}
}

func TestInitializeChallenge(t *testing.T) {
	_, servers, context, _ := generateTestContext(rand.Intn(10)+1, rand.Intn(10)+1)

	//Generate commitments
	var commits []Commitment
	var openings []abstract.Scalar
	for i := 0; i < len(servers); i++ {
		commit, open, _ := servers[i].GenerateCommitment(context)
		commits = append(commits, *commit)
		openings = append(openings, open)
	}

	//Normal execution
	challenge, err := InitializeChallenge(context, commits, openings)
	if challenge == nil || err != nil {
		t.Error("Cannot initialize challenge")
	}

	//Empty inputs
	challenge, err = InitializeChallenge(nil, commits, openings)
	if err == nil || challenge != nil {
		t.Error("Wrong check: Empty cs")
	}
	challenge, err = InitializeChallenge(context, nil, openings)
	if err == nil || challenge != nil {
		t.Error("Wrong check: Empty commits")
	}
	challenge, err = InitializeChallenge(context, commits, nil)
	if err == nil || challenge != nil {
		t.Error("Wrong check: Empty openings")
	}

	//Mismatch length between commits and openings
	challenge, err = InitializeChallenge(context, commits, openings[:len(openings)-2])
	if err == nil || challenge != nil {
		t.Error("Wrong check: Empty openings")
	}

	//Change an opening
	openings[0] = suite.Scalar().Zero()
	challenge, err = InitializeChallenge(context, commits, openings[:len(openings)-2])
	if err == nil || challenge != nil {
		t.Error("Invalid opening check")
	}
}

func TestCheckUpdateChallenge(t *testing.T) {
	//The following tests need at least 2 servers
	_, servers, context, _ := generateTestContext(rand.Intn(10)+1, rand.Intn(10)+2)

	//Generate commitments
	var commits []Commitment
	var openings []abstract.Scalar
	for i := 0; i < len(servers); i++ {
		commit, open, _ := servers[i].GenerateCommitment(context)
		commits = append(commits, *commit)
		openings = append(openings, open)
	}

	challenge, _ := InitializeChallenge(context, commits, openings)
	cs := challenge.cs

	//Normal execution
	err := servers[0].CheckUpdateChallenge(context, challenge)
	if err != nil {
		t.Error("Cannot update the challenge")
	}
	if len(challenge.sigs) != 1 {
		t.Error("Did not correctly add the signature")
	}

	//Duplicate signature
	challenge.sigs = append(challenge.sigs, challenge.sigs[0])
	err = servers[0].CheckUpdateChallenge(context, challenge)
	if err == nil {
		t.Error("Does not check for duplicates signatures")
	}
	challenge.sigs = []serverSignature{challenge.sigs[0]}

	//Altered signature
	fake := append([]byte("A"), challenge.sigs[0].sig...)
	challenge.sigs[0].sig = fake[:len(challenge.sigs[0].sig)]
	err = servers[0].CheckUpdateChallenge(context, challenge)
	if err == nil {
		t.Error("Wrond check of signature")
	}
	//Restore correct signature for the next tests
	challenge.sigs = nil
	servers[0].CheckUpdateChallenge(context, challenge)

	//Modify the challenge
	challenge.cs = suite.Scalar().Zero()
	err = servers[0].CheckUpdateChallenge(context, challenge)
	if err == nil {
		t.Error("Does not check the challenge")
	}
	challenge.cs = cs

	//Only appends if the challenge has not already done a round-robin
	for _, server := range servers[1:] {
		err = server.CheckUpdateChallenge(context, challenge)
		if err != nil {
			t.Errorf("Error during the round-robin at server %d", server.index)
		}
	}
	err = servers[0].CheckUpdateChallenge(context, challenge)
	if err != nil {
		t.Error("Error when closing the loop of the round-robin")
	}
	if len(challenge.sigs) != len(servers) {
		t.Errorf("Invalid number of signatures: %d instead of %d", len(challenge.sigs), len(servers))
	}

	//Change a commitment
	challenge.commits[0].commit = suite.Point().Mul(nil, suite.Scalar().One())
	err = servers[0].CheckUpdateChallenge(context, challenge)
	if err == nil {
		t.Error("Invalid commitment signature check")
	}
	challenge.commits[0].commit = suite.Point().Mul(nil, challenge.openings[0])

	//Change an opening
	challenge.openings[0] = suite.Scalar().Zero()
	err = servers[0].CheckUpdateChallenge(context, challenge)
	if err == nil {
		t.Error("Invalid opening check")
	}
}

func TestFinalizeChallenge(t *testing.T) {
	//The following tests need at least 2 servers
	_, servers, context, _ := generateTestContext(rand.Intn(10)+1, rand.Intn(10)+2)

	//Generate commitments
	var commits []Commitment
	var openings []abstract.Scalar
	for i := 0; i < len(servers); i++ {
		commit, open, _ := servers[i].GenerateCommitment(context)
		commits = append(commits, *commit)
		openings = append(openings, open)
	}

	challenge, _ := InitializeChallenge(context, commits, openings)

	//Makes every server update the challenge
	var err error
	for _, server := range servers[1:] {
		err = server.CheckUpdateChallenge(context, challenge)
		if err != nil {
			t.Errorf("Error during the round-robin at server %d", server.index)
		}
	}

	//Normal execution
	//Let's say that server 0 is the leader and received the message back
	servers[0].CheckUpdateChallenge(context, challenge)
	clientChallenge, err := FinalizeChallenge(context, challenge)
	if err != nil {
		t.Errorf("Error during finalization of the challenge")
	}
	//Check cs value
	if !clientChallenge.cs.Equal(challenge.cs) {
		t.Errorf("cs values does not match")
	}
	//Check number of signatures
	if len(clientChallenge.sigs) != len(challenge.sigs) {
		t.Errorf("Signature count does not match: got %d expected %d", len(clientChallenge.sigs), len(challenge.sigs))
	}

	//Empty inputs
	clientChallenge, err = FinalizeChallenge(nil, challenge)
	if err == nil || clientChallenge != nil {
		t.Errorf("Wrong check: Empty context")
	}
	clientChallenge, err = FinalizeChallenge(context, nil)
	if err == nil || clientChallenge != nil {
		t.Errorf("Wrong check: Empty challenge")
	}

	//Add a signature
	challenge.sigs = append(challenge.sigs, challenge.sigs[0])
	clientChallenge, err = FinalizeChallenge(context, challenge)
	if err == nil || clientChallenge != nil {
		t.Errorf("Wrong check: Higher signature count")
	}
	//Remove a signature
	challenge.sigs = challenge.sigs[:len(challenge.sigs)-2]
	clientChallenge, err = FinalizeChallenge(context, challenge)
	if err == nil || clientChallenge != nil {
		t.Errorf("Wrong check: Lower signature count")
	}
}

func TestInitializeServerMessage(t *testing.T) {
	clients, servers, context, _ := generateTestContext(1, 2)
	for _, server := range servers {
		if server.r == nil {
			t.Errorf("Error in r for server %d", server.index)
		}
	}
	T0, S, s, _ := clients[0].CreateRequest(context)
	tclient, v, w := clients[0].GenerateProofCommitments(context, T0, s)

	//Generate a valid challenge
	var commits []Commitment
	var openings []abstract.Scalar
	for i := 0; i < len(servers); i++ {
		commit, open, _ := servers[i].GenerateCommitment(context)
		commits = append(commits, *commit)
		openings = append(openings, open)
	}

	challenge, _ := InitializeChallenge(context, commits, openings)
	cs := challenge.cs

	//Sign the challenge
	for _, server := range servers {
		server.CheckUpdateChallenge(context, challenge)
	}

	clientChallenge, _ := FinalizeChallenge(context, challenge)

	c, r, _ := clients[0].GenerateProofResponses(context, s, clientChallenge, v, w)

	//Assemble the client message
	clientMessage := ClientMessage{sArray: S, t0: T0, context: *context,
		proof: ClientProof{cs: cs, c: *c, t: *tclient, r: *r}}

	//Normal execution
	servMsg := servers[0].InitializeServerMessage(&clientMessage)
	if servMsg == nil || len(servMsg.indexes) != 0 || len(servMsg.proofs) != 0 || len(servMsg.tags) != 0 || len(servMsg.sigs) != 0 {
		t.Error("Cannot initialize server message")
	}

	//Empty request
	servMsg = servers[0].InitializeServerMessage(nil)
	if servMsg != nil {
		t.Error("Wrong check: Empty request")
	}

}

func TestServerProtocol(t *testing.T) {
	clients, servers, context, _ := generateTestContext(1, 2)
	for _, server := range servers {
		if server.r == nil {
			t.Errorf("Error in r for server %d", server.index)
		}
	}
	T0, S, s, _ := clients[0].CreateRequest(context)
	tclient, v, w := clients[0].GenerateProofCommitments(context, T0, s)

	//Generate a valid challenge
	var commits []Commitment
	var openings []abstract.Scalar
	for i := 0; i < len(servers); i++ {
		commit, open, _ := servers[i].GenerateCommitment(context)
		commits = append(commits, *commit)
		openings = append(openings, open)
	}

	challenge, _ := InitializeChallenge(context, commits, openings)
	cs := challenge.cs

	//Sign the challenge
	for _, server := range servers {
		server.CheckUpdateChallenge(context, challenge)
	}

	clientChallenge, _ := FinalizeChallenge(context, challenge)

	c, r, _ := clients[0].GenerateProofResponses(context, s, clientChallenge, v, w)

	//Assemble the client message
	clientMessage := ClientMessage{sArray: S, t0: T0, context: *context,
		proof: ClientProof{cs: cs, c: *c, t: *tclient, r: *r}}
	//Original hash for later test
	hasher := sha512.New()
	var writer io.Writer = hasher
	data, _ := clientMessage.ToBytes()
	writer.Write(data)
	hash := hasher.Sum(nil)

	//Create the initial server message
	servMsg := ServerMessage{request: clientMessage, proofs: nil, tags: nil, sigs: nil, indexes: nil}

	//Normal execution for correct client
	err := servers[0].ServerProtocol(context, &servMsg)
	if err != nil {
		t.Errorf("Error in Server Protocol\n%s", err)
	}

	err = servers[1].ServerProtocol(context, &servMsg)
	if err != nil {
		t.Errorf("Error in Server Protocol for server 1\n%s", err)
	}

	//Check that elements were added to the message
	if len(servMsg.indexes) != 2 {
		t.Errorf("Incorrect number of elements added to the message: %d instead of 2", len(servMsg.indexes))
	}

	//Empty request
	emptyMsg := ServerMessage{request: ClientMessage{}, proofs: servMsg.proofs, tags: servMsg.tags, sigs: servMsg.sigs, indexes: servMsg.indexes}
	err = servers[0].ServerProtocol(context, &emptyMsg)
	if err == nil {
		t.Error("Wrong check: Empty request")
	}

	//Different lengths
	wrongMsg := ServerMessage{request: clientMessage, proofs: servMsg.proofs, tags: servMsg.tags, sigs: servMsg.sigs, indexes: servMsg.indexes}
	wrongMsg.indexes = wrongMsg.indexes[:len(wrongMsg.indexes)-2]
	err = servers[0].ServerProtocol(context, &wrongMsg)
	if err == nil {
		t.Error("Wrong check: different field length of indexes")
	}

	wrongMsg = ServerMessage{request: clientMessage, proofs: servMsg.proofs, tags: servMsg.tags, sigs: servMsg.sigs, indexes: servMsg.indexes}
	wrongMsg.tags = wrongMsg.tags[:len(wrongMsg.tags)-2]
	err = servers[0].ServerProtocol(context, &wrongMsg)
	if err == nil {
		t.Error("Wrong check: different field length of tags")
	}

	wrongMsg = ServerMessage{request: clientMessage, proofs: servMsg.proofs, tags: servMsg.tags, sigs: servMsg.sigs, indexes: servMsg.indexes}
	wrongMsg.proofs = wrongMsg.proofs[:len(wrongMsg.proofs)-2]
	err = servers[0].ServerProtocol(context, &wrongMsg)
	if err == nil {
		t.Error("Wrong check: different field length of proofs")
	}

	wrongMsg = ServerMessage{request: clientMessage, proofs: servMsg.proofs, tags: servMsg.tags, sigs: servMsg.sigs, indexes: servMsg.indexes}
	wrongMsg.sigs = wrongMsg.sigs[:len(wrongMsg.sigs)-2]
	err = servers[0].ServerProtocol(context, &wrongMsg)
	if err == nil {
		t.Error("Wrong check: different field length of signatures")
	}

	//Modify the client proof
	wrongClient := ServerMessage{request: clientMessage, proofs: servMsg.proofs, tags: servMsg.tags, sigs: servMsg.sigs, indexes: servMsg.indexes}
	wrongClient.request.proof = ClientProof{}
	err = servers[0].ServerProtocol(context, &wrongMsg)
	if err == nil {
		t.Error("Wrong check: invalid client proof")
	}

	//Too many calls
	err = servers[0].ServerProtocol(context, &servMsg)
	if err == nil {
		t.Errorf("Wrong check: Too many calls")
	}

	//The client request is left untouched
	hasher2 := sha512.New()
	var writer2 io.Writer = hasher2
	data2, _ := servMsg.request.ToBytes()
	writer2.Write(data2)
	hash2 := hasher2.Sum(nil)

	for i := range hash {
		if hash[i] != hash2[i] {
			t.Error("Client's request modified")
			break
		}
	}

	//Normal execution for misbehaving client
	misbehavingMsg := ServerMessage{request: clientMessage, proofs: nil, tags: nil, sigs: nil, indexes: nil}
	misbehavingMsg.request.sArray[2] = suite.Point().Null() //change the commitment for server 0
	err = servers[0].ServerProtocol(context, &misbehavingMsg)
	if err != nil {
		t.Errorf("Error in Server Protocol for misbehaving client\n%s", err)
	}

	err = servers[1].ServerProtocol(context, &misbehavingMsg)
	if err != nil {
		t.Errorf("Error in Server Protocol for misbehaving client and server 1\n%s", err)
	}

}

func TestGenerateServerProof(t *testing.T) {
	clients, servers, context, _ := generateTestContext(1, 2)
	T0, S, s, _ := clients[0].CreateRequest(context)
	tclient, v, w := clients[0].GenerateProofCommitments(context, T0, s)

	//Generate a valid challenge
	var commits []Commitment
	var openings []abstract.Scalar
	for i := 0; i < len(servers); i++ {
		commit, open, _ := servers[i].GenerateCommitment(context)
		commits = append(commits, *commit)
		openings = append(openings, open)
	}

	challenge, _ := InitializeChallenge(context, commits, openings)
	cs := challenge.cs

	//Sign the challenge
	for _, server := range servers {
		server.CheckUpdateChallenge(context, challenge)
	}

	clientChallenge, _ := FinalizeChallenge(context, challenge)
	c, r, _ := clients[0].GenerateProofResponses(context, s, clientChallenge, v, w)

	//Assemble the client message
	clientMessage := ClientMessage{sArray: S, t0: T0, context: *context,
		proof: ClientProof{cs: cs, c: *c, t: *tclient, r: *r}}

	//Create the initial server message
	servMsg := ServerMessage{request: clientMessage, proofs: nil, tags: nil, sigs: nil, indexes: nil}

	//Prepare the proof
	hasher := sha512.New()
	var writer io.Writer = hasher
	suite.Point().Mul(servMsg.request.sArray[0], servers[0].private).MarshalTo(writer)
	hash := hasher.Sum(nil)
	rand := suite.Cipher(hash)
	secret := suite.Scalar().Pick(rand)

	inv := suite.Scalar().Inv(secret)
	exp := suite.Scalar().Mul(servers[0].r, inv)
	T := suite.Point().Mul(T0, exp)

	//Normal execution
	proof, err := servers[0].generateServerProof(context, secret, T, &servMsg)
	if err != nil || proof == nil {
		t.Error("Cannot generate normal server proof")
	}

	//Correct format
	if proof.t1 == nil || proof.t2 == nil || proof.t3 == nil {
		t.Error("Incorrect tags in proof")
	}
	if proof.c == nil {
		t.Error("Incorrect challenge")
	}
	if proof.r1 == nil || proof.r2 == nil {
		t.Error("Incorrect responses")
	}

	//Invalid inputs
	proof, err = servers[0].generateServerProof(nil, secret, T, &servMsg)
	if err == nil || proof != nil {
		t.Error("Wrong check: Invalid context")
	}
	proof, err = servers[0].generateServerProof(context, nil, T, &servMsg)
	if err == nil || proof != nil {
		t.Error("Wrong check: Invalid secret")
	}
	proof, err = servers[0].generateServerProof(context, secret, nil, &servMsg)
	if err == nil || proof != nil {
		t.Error("Wrong check: Invalid tag")
	}
	proof, err = servers[0].generateServerProof(context, secret, T, nil)
	if err == nil || proof != nil {
		t.Error("Wrong check: Invalid Server Message")
	}
}

func TestVerifyServerProof(t *testing.T) {
	clients, servers, context, _ := generateTestContext(1, 3)
	T0, S, s, _ := clients[0].CreateRequest(context)
	tclient, v, w := clients[0].GenerateProofCommitments(context, T0, s)

	//Generate a valid challenge
	var commits []Commitment
	var openings []abstract.Scalar
	for i := 0; i < len(servers); i++ {
		commit, open, _ := servers[i].GenerateCommitment(context)
		commits = append(commits, *commit)
		openings = append(openings, open)
	}

	challenge, _ := InitializeChallenge(context, commits, openings)
	cs := challenge.cs

	//Normal execution
	for _, server := range servers {
		server.CheckUpdateChallenge(context, challenge)
	}

	clientChallenge, _ := FinalizeChallenge(context, challenge)
	c, r, _ := clients[0].GenerateProofResponses(context, s, clientChallenge, v, w)

	//Assemble the client message
	clientMessage := ClientMessage{sArray: S, t0: T0, context: *context,
		proof: ClientProof{cs: cs, c: *c, t: *tclient, r: *r}}

	servMsg := ServerMessage{request: clientMessage, proofs: nil, tags: nil, sigs: nil, indexes: nil}

	//Prepare the proof
	hasher := sha512.New()
	var writer io.Writer = hasher
	suite.Point().Mul(servMsg.request.sArray[0], servers[0].private).MarshalTo(writer)
	hash := hasher.Sum(nil)
	rand := suite.Cipher(hash)
	secret := suite.Scalar().Pick(rand)

	inv := suite.Scalar().Inv(secret)
	exp := suite.Scalar().Mul(servers[0].r, inv)
	T := suite.Point().Mul(T0, exp)

	//Generate the proof
	proof, _ := servers[0].generateServerProof(context, secret, T, &servMsg)
	servMsg.proofs = append(servMsg.proofs, *proof)
	servMsg.tags = append(servMsg.tags, T)
	servMsg.indexes = append(servMsg.indexes, servers[0].index)

	//Signs our message
	data, _ := servMsg.request.ToBytes()
	temp, _ := T.MarshalBinary()
	data = append(data, temp...)
	temp, _ = proof.ToBytes()
	data = append(data, temp...)
	data = append(data, []byte(strconv.Itoa(servers[0].index))...)
	sign, _ := ECDSASign(servers[0].private, data)
	signature := serverSignature{sig: sign, index: servers[0].index}
	servMsg.sigs = append(servMsg.sigs, signature)

	/*err := servers[1].ServerProtocol(context, &servMsg)
	if err != nil {
		t.Errorf("Error in Server Protocol after proof\n%s", err)
	}*/

	//Verify first server proof
	check := verifyServerProof(context, 0, &servMsg)
	if !check {
		t.Error("Cannot verify first valid normal server proof")
	}

	servers[1].ServerProtocol(context, &servMsg)

	//Verify any server proof
	check = verifyServerProof(context, 1, &servMsg)
	if !check {
		t.Error("Cannot verify valid normal server proof")
	}

	saveProof := serverProof{c: servMsg.proofs[1].c,
		t1: servMsg.proofs[1].t1,
		t2: servMsg.proofs[1].t2,
		t3: servMsg.proofs[1].t3,
		r1: servMsg.proofs[1].r1,
		r2: servMsg.proofs[1].r2,
	}

	//Check inputs
	servMsg.proofs[1].c = nil
	check = verifyServerProof(context, 1, &servMsg)
	if check {
		t.Error("Error in challenge verification")
	}
	servMsg.proofs[1].c = saveProof.c

	servMsg.proofs[1].t1 = nil
	check = verifyServerProof(context, 1, &servMsg)
	if check {
		t.Error("Error in t1 verification")
	}
	servMsg.proofs[1].t1 = saveProof.t1

	servMsg.proofs[1].t2 = nil
	check = verifyServerProof(context, 1, &servMsg)
	if check {
		t.Error("Error in t2 verification")
	}
	servMsg.proofs[1].t2 = saveProof.t2

	servMsg.proofs[1].t3 = nil
	check = verifyServerProof(context, 1, &servMsg)
	if check {
		t.Error("Error in t3 verification")
	}
	servMsg.proofs[1].t3 = saveProof.t3

	servMsg.proofs[1].r1 = nil
	check = verifyServerProof(context, 1, &servMsg)
	if check {
		t.Error("Error in r1 verification")
	}
	servMsg.proofs[1].r1 = saveProof.r1

	servMsg.proofs[1].r2 = nil
	check = verifyServerProof(context, 1, &servMsg)
	if check {
		t.Error("Error in r2 verification")
	}
	servMsg.proofs[1].r2 = saveProof.r2

	//Invalid context
	check = verifyServerProof(nil, 1, &servMsg)
	if check {
		t.Error("Wrong check: Invalid context")
	}

	//nil message
	check = verifyServerProof(context, 1, nil)
	if check {
		t.Error("Wrong check: Invalid message")
	}

	//Invalid value of i
	check = verifyServerProof(context, 2, &servMsg)
	if check {
		t.Error("Wrong check: Invalid i value")
	}
	check = verifyServerProof(context, -2, &servMsg)
	if check {
		t.Error("Wrong check: Negative i value")
	}

}

func TestGenerateMisbehavingProof(t *testing.T) {
	clients, servers, context, _ := generateTestContext(1, 2)
	T0, S, s, _ := clients[0].CreateRequest(context)
	tclient, v, w := clients[0].GenerateProofCommitments(context, T0, s)

	//Generate a valid challenge
	var commits []Commitment
	var openings []abstract.Scalar
	for i := 0; i < len(servers); i++ {
		commit, open, _ := servers[i].GenerateCommitment(context)
		commits = append(commits, *commit)
		openings = append(openings, open)
	}

	challenge, _ := InitializeChallenge(context, commits, openings)
	cs := challenge.cs

	//Generate the challenge
	for _, server := range servers {
		server.CheckUpdateChallenge(context, challenge)
	}

	clientChallenge, _ := FinalizeChallenge(context, challenge)

	c, r, _ := clients[0].GenerateProofResponses(context, s, clientChallenge, v, w)

	//Assemble the client message
	clientMessage := ClientMessage{sArray: S, t0: T0, context: *context,
		proof: ClientProof{cs: cs, c: *c, t: *tclient, r: *r}}

	proof, err := servers[0].generateMisbehavingProof(context, clientMessage.sArray[0])
	if err != nil || proof == nil {
		t.Error("Cannot generate misbehaving proof")
	}

	//Correct format
	if proof.t1 == nil {
		t.Error("t1 nil for misbehaving proof")
	}
	if proof.t2 == nil {
		t.Error("t2 nil for misbehaving proof")
	}
	if proof.t3 == nil {
		t.Error("t3 nil for misbehaving proof")
	}
	if proof.c == nil {
		t.Error("c nil for misbehaving proof")
	}
	if proof.r1 == nil {
		t.Error("r1 nil for misbehaving proof")
	}
	if proof.r2 != nil {
		t.Error("r2 not nil for misbehaving proof")
	}

	//Invalid inputs
	proof, err = servers[0].generateMisbehavingProof(nil, clientMessage.sArray[0])
	if err == nil || proof != nil {
		t.Error("Wrong check: Invalid context")
	}
	proof, err = servers[0].generateMisbehavingProof(context, nil)
	if err == nil || proof != nil {
		t.Error("Wrong check: Invalid Z")
	}
}

func TestVerifyMisbehavingProof(t *testing.T) {
	clients, servers, context, _ := generateTestContext(1, 2)
	T0, S, s, _ := clients[0].CreateRequest(context)
	tclient, v, w := clients[0].GenerateProofCommitments(context, T0, s)

	//Generate a valid challenge
	var commits []Commitment
	var openings []abstract.Scalar
	for i := 0; i < len(servers); i++ {
		commit, open, _ := servers[i].GenerateCommitment(context)
		commits = append(commits, *commit)
		openings = append(openings, open)
	}

	challenge, _ := InitializeChallenge(context, commits, openings)
	cs := challenge.cs

	//Normal execution
	for _, server := range servers {
		server.CheckUpdateChallenge(context, challenge)
	}

	clientChallenge, _ := FinalizeChallenge(context, challenge)

	c, r, _ := clients[0].GenerateProofResponses(context, s, clientChallenge, v, w)

	//Assemble the client message
	clientMessage := ClientMessage{sArray: S, t0: T0, context: *context,
		proof: ClientProof{cs: cs, c: *c, t: *tclient, r: *r}}

	proof, _ := servers[0].generateMisbehavingProof(context, clientMessage.sArray[0])

	check := verifyMisbehavingProof(context, 0, proof, clientMessage.sArray[0])
	if !check {
		t.Error("Cannot verify valid misbehaving proof")
	}

	//Invalid inputs
	check = verifyMisbehavingProof(nil, 0, proof, clientMessage.sArray[0])
	if check {
		t.Error("Wrong check: Invalid context")
	}

	check = verifyMisbehavingProof(context, 1, proof, clientMessage.sArray[0])
	if check {
		t.Error("Wrong check: Invalid index")
	}
	check = verifyMisbehavingProof(context, -1, proof, clientMessage.sArray[0])
	if check {
		t.Error("Wrong check: Negative index")
	}

	check = verifyMisbehavingProof(context, 0, nil, clientMessage.sArray[0])
	if check {
		t.Error("Wrong check: Missing proof")
	}

	check = verifyMisbehavingProof(context, 0, proof, nil)
	if check {
		t.Error("Wrong check: Invalid Z")
	}

	//Modify proof values

	proof, _ = servers[0].generateMisbehavingProof(context, clientMessage.sArray[0])
	saveProof := serverProof{
		c:  proof.c,
		t1: proof.t1,
		t2: proof.t2,
		t3: proof.t3,
		r1: proof.r1,
		r2: proof.r2,
	}

	//Check inputs
	proof.c = nil
	check = verifyMisbehavingProof(context, 0, proof, clientMessage.sArray[0])
	if check {
		t.Error("Error in challenge verification")
	}
	proof.c = saveProof.c

	proof.t1 = nil
	check = verifyMisbehavingProof(context, 0, proof, clientMessage.sArray[0])
	if check {
		t.Error("Error in t1 verification")
	}
	proof.t1 = saveProof.t1

	proof.t2 = nil
	check = verifyMisbehavingProof(context, 0, proof, clientMessage.sArray[0])
	if check {
		t.Error("Error in t2 verification")
	}
	proof.t2 = saveProof.t2

	proof.t3 = nil
	check = verifyMisbehavingProof(context, 0, proof, clientMessage.sArray[0])
	if check {
		t.Error("Error in t3 verification")
	}
	proof.t3 = saveProof.t3

	proof.r1 = nil
	check = verifyMisbehavingProof(context, 0, proof, clientMessage.sArray[0])
	if check {
		t.Error("Error in r1 verification")
	}
	proof.r1 = saveProof.r1

	proof.r2 = suite.Scalar().One()
	check = verifyMisbehavingProof(context, 0, proof, clientMessage.sArray[0])
	if check {
		t.Error("Error in r2 verification")
	}
	proof.r2 = saveProof.r2
	// TODO: Complete the tests
}

func TestGenerateNewRoundSecret(t *testing.T) {
	_, servers, _, _ := generateTestContext(1, 1)
	R := servers[0].GenerateNewRoundSecret()
	if R == nil {
		t.Error("Cannot generate new round secret")
	}
	if R.Equal(suite.Point().Mul(nil, suite.Scalar().One())) {
		t.Error("R is the generator")
	}
	if servers[0].r == nil {
		t.Error("r was not saved to the server")
	}
	if !R.Equal(suite.Point().Mul(nil, servers[0].r)) {
		t.Error("Mismatch between r and R")
	}
}

func TestToBytes_ServerProof(t *testing.T) {
	clients, servers, context, _ := generateTestContext(1, 2)
	T0, S, s, _ := clients[0].CreateRequest(context)
	tclient, v, w := clients[0].GenerateProofCommitments(context, T0, s)

	//Generate a valid challenge
	var commits []Commitment
	var openings []abstract.Scalar
	for i := 0; i < len(servers); i++ {
		commit, open, _ := servers[i].GenerateCommitment(context)
		commits = append(commits, *commit)
		openings = append(openings, open)
	}

	challenge, _ := InitializeChallenge(context, commits, openings)
	cs := challenge.cs

	//Create challenge
	for _, server := range servers {
		server.CheckUpdateChallenge(context, challenge)
	}

	clientChallenge, _ := FinalizeChallenge(context, challenge)

	c, r, _ := clients[0].GenerateProofResponses(context, s, clientChallenge, v, w)

	//Assemble the client message
	clientMessage := ClientMessage{sArray: S, t0: T0, context: *context,
		proof: ClientProof{cs: cs, c: *c, t: *tclient, r: *r}}

	servMsg := ServerMessage{request: clientMessage, proofs: nil, tags: nil, sigs: nil, indexes: nil}

	servers[0].ServerProtocol(context, &servMsg)

	//Normal execution for correct proof
	data, err := servMsg.proofs[0].ToBytes()
	if err != nil || data == nil {
		t.Error("Cannot convert normal proof")
	}
	//Normal execution for correct misbehaving proof
	proof, _ := servers[0].generateMisbehavingProof(context, S[0])
	data, err = proof.ToBytes()
	if err != nil || data == nil {
		t.Error("Cannot convert misbehaving proof")
	}

}
