package dagapython

import (
	"crypto/sha512"
	"io"
	"math/rand"
	"testing"

	"gopkg.in/dedis/crypto.v0/abstract"
)

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
	err = ECDSAVerify(suite.Point().Mul(nil, servers[0].private), msg, commit.Sig.sig)
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
	err := VerifyCommitmentSignature(context, &commits)
	if err != nil {
		t.Error("Cannot verify the signatures for a legit commit array")
	}

	//Change a random index
	i := rand.Intn(len(servers))
	commits[i].Sig.index = i + 1
	err = VerifyCommitmentSignature(context, &commits)
	if err == nil {
		t.Errorf("Cannot verify matching indexes for %d", i)
	}
	commits[i].Sig.index = i + 1

	//Change a signature
	//Code shown as not covered, but it does detect the modification and returns an error
	sig := commits[i].Sig.sig
	sig = append([]byte("A"), sig...)
	sig = sig[:len(commits[i].Sig.sig)]
	commits[i].Sig.sig = sig
	err = VerifyCommitmentSignature(context, &commits)
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
	cs, err := CheckOpenings(context, &commits, &openings)
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

	//Change the length of the openings
	CutOpenings := openings[:len(openings)-1]
	cs, err = CheckOpenings(context, &commits, &CutOpenings)
	if err == nil {
		t.Error("Invalid length check")
	}
	if cs != nil {
		t.Error("cs not nil on length error")
	}

	//Change a random opening
	i := rand.Intn(len(servers))
	openings[i] = suite.Scalar().Zero()
	cs, err = CheckOpenings(context, &commits, &openings)
	if err == nil {
		t.Error("Invalid opening check")
	}
	if cs != nil {
		t.Error("cs not nil on opening error")
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

	cs, _ := CheckOpenings(context, &commits, &openings)
	challenge := Challenge{Sigs: nil, cs: cs}

	//Normal execution
	err := servers[0].CheckUpdateChallenge(context, cs, &challenge)
	if err != nil {
		t.Error("Cannot update the challenge")
	}
	if len(challenge.Sigs) != 1 {
		t.Error("Did not correctly add the signature")
	}

	//Duplicate signature
	challenge.Sigs = append(challenge.Sigs, challenge.Sigs[0])
	err = servers[0].CheckUpdateChallenge(context, cs, &challenge)
	if err == nil {
		t.Error("Does not check for duplicates signatures")
	}
	challenge.Sigs = []ServerSignature{challenge.Sigs[0]}

	//Altered signature
	fake := append([]byte("A"), challenge.Sigs[0].sig...)
	challenge.Sigs[0].sig = fake[:len(challenge.Sigs[0].sig)]
	err = servers[0].CheckUpdateChallenge(context, cs, &challenge)
	if err == nil {
		t.Error("Wrond check of signature")
	}
	//Restore correct signature for next tests
	challenge.Sigs = nil
	servers[0].CheckUpdateChallenge(context, cs, &challenge)

	//Modify the challenge
	challenge.cs = suite.Scalar().Zero()
	err = servers[0].CheckUpdateChallenge(context, cs, &challenge)
	if err == nil {
		t.Error("Does not check the challenge")
	}
	challenge.cs = cs

	//Only appends if the challenge has not already do a round-robin
	for _, server := range servers[1:] {
		err = server.CheckUpdateChallenge(context, cs, &challenge)
		if err != nil {
			t.Errorf("Error during the round-robin at server %d", server.index)
		}
	}
	err = servers[0].CheckUpdateChallenge(context, cs, &challenge)
	if err != nil {
		t.Error("Error when closing the loop of the round-robin")
	}
	if len(challenge.Sigs) != len(servers) {
		t.Errorf("Invalid number of signatures: %d instead of %d", len(challenge.Sigs), len(servers))
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

	cs, _ := CheckOpenings(context, &commits, &openings)
	challenge := Challenge{Sigs: nil, cs: cs}

	//Normal execution
	for _, server := range servers {
		server.CheckUpdateChallenge(context, cs, &challenge)
	}

	c, r, _ := clients[0].GenerateProofResponses(context, s, &challenge, v, w)

	//Assemble the client message
	clientMessage := ClientMessage{S: S, T0: T0, context: *context,
		proof: ClientProof{cs: cs, c: *c, t: *tclient, r: *r}}

	servMsg := ServerMessage{request: clientMessage, proofs: nil, tags: nil, sigs: nil, indexes: nil}

	//Normal execution
	err := servers[0].ServerProtocol(context, &servMsg)
	if err != nil {
		t.Errorf("Error in Server Protocol\n%s", err)
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

	cs, _ := CheckOpenings(context, &commits, &openings)
	challenge := Challenge{Sigs: nil, cs: cs}

	//Normal execution
	for _, server := range servers {
		server.CheckUpdateChallenge(context, cs, &challenge)
	}

	c, r, _ := clients[0].GenerateProofResponses(context, s, &challenge, v, w)

	//Assemble the client message
	clientMessage := ClientMessage{S: S, T0: T0, context: *context,
		proof: ClientProof{cs: cs, c: *c, t: *tclient, r: *r}}

	servMsg := ServerMessage{request: clientMessage, proofs: nil, tags: nil, sigs: nil, indexes: nil}

	//Prepare the proof
	hasher := sha512.New()
	var writer io.Writer = hasher
	suite.Point().Mul(servMsg.request.S[0], servers[0].private).MarshalTo(writer)
	hash := hasher.Sum(nil)
	secret := suite.Scalar().SetBytes(hash[:])

	inv := suite.Scalar().Inv(secret)
	exp := suite.Scalar().Mul(servers[0].r, inv)
	T := suite.Point().Mul(T0, exp)

	//Normal execution
	proof, err := servers[0].GenerateServerProof(context, secret, T, &servMsg)
	if err != nil || proof == nil {
		t.Error("Cannot generate normal server proof")
	}

	// TODO: Checks on the format of the proof
}

func TestVerifyServerProof(t *testing.T) {
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

	cs, _ := CheckOpenings(context, &commits, &openings)
	challenge := Challenge{Sigs: nil, cs: cs}

	//Normal execution
	for _, server := range servers {
		server.CheckUpdateChallenge(context, cs, &challenge)
	}

	c, r, _ := clients[0].GenerateProofResponses(context, s, &challenge, v, w)

	//Assemble the client message
	clientMessage := ClientMessage{S: S, T0: T0, context: *context,
		proof: ClientProof{cs: cs, c: *c, t: *tclient, r: *r}}

	servMsg := ServerMessage{request: clientMessage, proofs: nil, tags: nil, sigs: nil, indexes: nil}

	//Prepare the proof
	hasher := sha512.New()
	var writer io.Writer = hasher
	suite.Point().Mul(servMsg.request.S[0], servers[0].private).MarshalTo(writer)
	hash := hasher.Sum(nil)
	secret := suite.Scalar().SetBytes(hash[:])

	inv := suite.Scalar().Inv(secret)
	exp := suite.Scalar().Mul(servers[0].r, inv)
	T := suite.Point().Mul(T0, exp)

	//Normal execution
	proof, _ := servers[0].GenerateServerProof(context, secret, T, &servMsg)
	servMsg.proofs = append(servMsg.proofs, *proof)

	check := VerifyServerProof(context, 0, &servMsg)
	if !check {
		t.Error("Cannot verify valid normal server proof")
	}
	// TODO: Complete the tests
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

	cs, _ := CheckOpenings(context, &commits, &openings)
	challenge := Challenge{Sigs: nil, cs: cs}

	//Normal execution
	for _, server := range servers {
		server.CheckUpdateChallenge(context, cs, &challenge)
	}

	c, r, _ := clients[0].GenerateProofResponses(context, s, &challenge, v, w)

	//Assemble the client message
	clientMessage := ClientMessage{S: S, T0: T0, context: *context,
		proof: ClientProof{cs: cs, c: *c, t: *tclient, r: *r}}

	proof, err := servers[0].GenerateMisbehavingProof(context, clientMessage.S[0])
	if err != nil || proof == nil {
		t.Error("Cannot generate misbehaving proof")
	}
	if proof.r2 != nil {
		t.Error("r2 not nil for misbehaving proof")
	}
	// TODO: Additionnal checks

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

	cs, _ := CheckOpenings(context, &commits, &openings)
	challenge := Challenge{Sigs: nil, cs: cs}

	//Normal execution
	for _, server := range servers {
		server.CheckUpdateChallenge(context, cs, &challenge)
	}

	c, r, _ := clients[0].GenerateProofResponses(context, s, &challenge, v, w)

	//Assemble the client message
	clientMessage := ClientMessage{S: S, T0: T0, context: *context,
		proof: ClientProof{cs: cs, c: *c, t: *tclient, r: *r}}

	proof, _ := servers[0].GenerateMisbehavingProof(context, clientMessage.S[0])

	check := VerifyMisbehavingProof(context, 0, proof, clientMessage.S[0])
	if !check {
		t.Error("Cannot verify valid misbehaving proof")
	}

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

	cs, _ := CheckOpenings(context, &commits, &openings)
	challenge := Challenge{Sigs: nil, cs: cs}

	//Normal execution
	for _, server := range servers {
		server.CheckUpdateChallenge(context, cs, &challenge)
	}

	c, r, _ := clients[0].GenerateProofResponses(context, s, &challenge, v, w)

	//Assemble the client message
	clientMessage := ClientMessage{S: S, T0: T0, context: *context,
		proof: ClientProof{cs: cs, c: *c, t: *tclient, r: *r}}

	servMsg := ServerMessage{request: clientMessage, proofs: nil, tags: nil, sigs: nil, indexes: nil}

	servers[0].ServerProtocol(context, &servMsg)

	//Normal execution for correct proof
	data, err := servMsg.proofs[0].ToBytes()
	if err != nil || data == nil {
		t.Error("Cannot convert normal proof")
	}

	proof, _ := servers[0].GenerateMisbehavingProof(context, S[0])
	data, err = proof.ToBytes()
	if err != nil || data == nil {
		t.Error("Cannot convert misbehaving proof")
	}

}
