package dagapython

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
)

func TestCreateClient(t *testing.T) {
	//Normal execution
	i := rand.Int()
	s := suite.Scalar().Pick(random.Stream)
	client, err := CreateClient(i, s)
	if err != nil || client.index != i || !client.private.Equal(s) {
		t.Error("Cannot initialize a new client with a given private key")
	}

	client, err = CreateClient(i, nil)
	if err != nil {
		t.Error("Cannot create a new client without a private key")
	}

	//Invalid input
	client, err = CreateClient(-2, s)
	if err == nil {
		t.Error("Wrong check: Invalid index")
	}

}

func TestGetPublicKey_Client(t *testing.T) {
	client, _ := CreateClient(0, suite.Scalar().Pick(random.Stream))
	P := client.GetPublicKey()
	if P == nil {
		t.Error("Cannot get public key")
	}
}

func TestCreateRequest(t *testing.T) {
	//Normal execution
	clients, servers, context, _ := generateTestContext(rand.Intn(10)+1, rand.Intn(10)+1)
	T0, S, s, err := clients[0].CreateRequest(context)
	if err != nil {
		assert.Equal(t, T0, nil, "T0 not nil on error")
		assert.Equal(t, S, nil, "S not nil on error")
		assert.Equal(t, s, nil, "s not nil on error")
		t.Error("Cannot create request under regular context")
	}

	if T0 == nil {
		t.Error("T0 empty")
	}
	if T0.Equal(suite.Point().Null()) {
		t.Error("T0 is the null point")
	}

	if S == nil {
		t.Error("S is empty")
	}
	if len(S) != len(servers)+2 {
		t.Errorf("S has the wrong length: %d instead of %d", len(S), len(servers)+2)
	}
	for i, temp := range S {
		if temp.Equal(suite.Point().Null()) {
			t.Errorf("Null point in S at position %d", i)
		}
	}

	if s == nil {
		t.Error("s is empty")
	}
}

func TestGenerateProofCommitments(t *testing.T) {
	clients, _, context, _ := generateTestContext(rand.Intn(10)+1, rand.Intn(10)+1)
	T0, _, s, _ := clients[0].CreateRequest(context)

	tproof, v, w := clients[0].GenerateProofCommitments(context, T0, s)
	if tproof == nil {
		t.Error("t is empty")
	}
	if v == nil {
		t.Error("t is empty")
	}
	if w == nil {
		t.Error("t is empty")
	}

	if len(*tproof) != 3*len(clients) {
		t.Errorf("Wrong length of t: %d instead of %d", len(*tproof), 3*len(clients))
	}
	if len(*v) != 2*len(clients) {
		t.Errorf("Wrong length of v: %d instead of %d", len(*v), 2*len(clients))
	}
	if len(*w) != len(clients) {
		t.Errorf("Wrong length of w: %d instead of %d", len(*w), len(clients))
	}
}

func TestGenerateProofResponses(t *testing.T) {
	clients, servers, context, _ := generateTestContext(rand.Intn(10)+1, rand.Intn(10)+1)
	T0, _, s, _ := clients[0].CreateRequest(context)
	_, v, w := clients[0].GenerateProofCommitments(context, T0, s)

	//Dumb challenge generation
	cs := suite.Scalar().Pick(random.Stream)
	msg, _ := cs.MarshalBinary()
	var sigs []ServerSignature
	//Make each test server sign the challenge
	for _, server := range servers {
		sig, e := ECDSASign(server.private, msg)
		if e != nil {
			t.Errorf("Cannot sign the challenge for server %d", server.index)
		}
		sigs = append(sigs, ServerSignature{index: server.index, sig: sig})
	}
	challenge := Challenge{cs: cs, Sigs: sigs}

	//Normal execution
	c, r, err := clients[0].GenerateProofResponses(context, s, &challenge, v, w)
	if err != nil {
		t.Error("Cannot generate proof responses")
	}

	if len(*c) != len(clients) {
		t.Errorf("Wrong length of c: %d instead of %d", len(*c), len(clients))
	}
	if len(*r) != 2*len(clients) {
		t.Errorf("Wrong length of r: %d instead of %d", len(*r), 2*len(clients))
	}

	for i, temp := range *c {
		if temp == nil {
			t.Errorf("nil in c at index %d", i)
		}
	}
	for i, temp := range *r {
		if temp == nil {
			t.Errorf("nil in r at index %d", i)
		}
	}

	//Incorrect challenges
	var fake abstract.Scalar
	for {
		fake = suite.Scalar().Pick(random.Stream)
		if !fake.Equal(cs) {
			break
		}
	}
	wrongChallenge := Challenge{cs: fake, Sigs: sigs}
	c, r, err = clients[0].GenerateProofResponses(context, s, &wrongChallenge, v, w)
	if err == nil {
		t.Error("Cannot verify the message")
	}
	if c != nil {
		t.Error("c not nil on message error")
	}
	if r != nil {
		t.Error("r not nil on message error")
	}

	//Signature modification
	newsig := append([]byte("A"), sigs[0].sig...)
	newsig = newsig[:len(sigs[0].sig)]
	sigs[0].sig = newsig
	SigChallenge := Challenge{cs: cs, Sigs: sigs}
	c, r, err = clients[0].GenerateProofResponses(context, s, &SigChallenge, v, w)
	if err == nil {
		t.Error("Cannot verify the message")
	}
	if c != nil {
		t.Error("c not nil on signature error")
	}
	if r != nil {
		t.Error("r not nil on signature error")
	}
}

func TestVerifyClientProof(t *testing.T) {
	clients, servers, context, _ := generateTestContext(rand.Intn(10)+1, rand.Intn(10)+1)
	T0, S, s, _ := clients[0].CreateRequest(context)
	tproof, v, w := clients[0].GenerateProofCommitments(context, T0, s)

	//Dumb challenge generation
	cs := suite.Scalar().Pick(random.Stream)
	msg, _ := cs.MarshalBinary()
	var sigs []ServerSignature
	//Make each test server sign the challenge
	for _, server := range servers {
		sig, e := ECDSASign(server.private, msg)
		if e != nil {
			t.Errorf("Cannot sign the challenge for server %d", server.index)
		}
		sigs = append(sigs, ServerSignature{index: server.index, sig: sig})
	}
	challenge := Challenge{cs: cs, Sigs: sigs}

	//Generate the final proof
	c, r, _ := clients[0].GenerateProofResponses(context, s, &challenge, v, w)

	ClientMsg := ClientMessage{context: ContextEd25519{G: Members{X: context.G.X, Y: context.G.Y}, R: context.R, H: context.H},
		T0:    T0,
		S:     S,
		proof: ClientProof{c: *c, cs: cs, r: *r, t: *tproof}}

	//Normal execution
	check := VerifyClientProof(ClientMsg)
	if !check {
		t.Error("Cannot verify client proof")
	}

	//Modify the value of some commitments
	ScratchMsg := ClientMsg
	i := rand.Intn(len(clients))
	ttemp := ScratchMsg.proof.t[3*i].Clone()
	ScratchMsg.proof.t[3*i] = suite.Point().Null()
	check = VerifyClientProof(ScratchMsg)
	if check {
		t.Errorf("Incorrect check of t at index %d", 3*i)
	}
	ScratchMsg.proof.t[3*i] = ttemp.Clone()

	ttemp = ScratchMsg.proof.t[3*i+1].Clone()
	ScratchMsg.proof.t[3*i+1] = suite.Point().Null()
	check = VerifyClientProof(ScratchMsg)
	if check {
		t.Errorf("Incorrect check of t at index %d", 3*i+1)
	}
	ScratchMsg.proof.t[3*i+1] = ttemp.Clone()

	ttemp = ScratchMsg.proof.t[3*i+2].Clone()
	ScratchMsg.proof.t[3*i+2] = suite.Point().Null()
	check = VerifyClientProof(ScratchMsg)
	if check {
		t.Errorf("Incorrect check of t at index %d", 3*i+2)
	}
	ScratchMsg.proof.t[3*i+2] = ttemp.Clone()

	//Modify the value of the challenge
	ScratchMsg.proof.cs = suite.Scalar().Zero()
	check = VerifyClientProof(ScratchMsg)
	if check {
		t.Errorf("Incorrect check of the challenge")
	}
}

func TestValidateClientMessage(t *testing.T) {
	clients, servers, context, _ := generateTestContext(rand.Intn(10)+1, rand.Intn(10)+1)
	T0, S, s, _ := clients[0].CreateRequest(context)
	tproof, v, w := clients[0].GenerateProofCommitments(context, T0, s)

	//Dumb challenge generation
	cs := suite.Scalar().Pick(random.Stream)
	msg, _ := cs.MarshalBinary()
	var sigs []ServerSignature
	//Make each test server sign the challenge
	for _, server := range servers {
		sig, e := ECDSASign(server.private, msg)
		if e != nil {
			t.Errorf("Cannot sign the challenge for server %d", server.index)
		}
		sigs = append(sigs, ServerSignature{index: server.index, sig: sig})
	}
	challenge := Challenge{cs: cs, Sigs: sigs}

	//Generate the final proof
	c, r, _ := clients[0].GenerateProofResponses(context, s, &challenge, v, w)

	ClientMsg := ClientMessage{context: ContextEd25519{G: Members{X: context.G.X, Y: context.G.Y}, R: context.R, H: context.H},
		T0:    T0,
		S:     S,
		proof: ClientProof{c: *c, cs: cs, r: *r, t: *tproof}}

	//Normal execution
	check := VerifyClientProof(ClientMsg)
	if !check {
		t.Error("Cannot verify client proof")
	}

	//Modifying the length of various elements
	ScratchMsg := ClientMsg
	ScratchMsg.proof.c = append(ScratchMsg.proof.c, suite.Scalar().Pick(random.Stream))
	check = VerifyClientProof(ScratchMsg)
	if check {
		t.Errorf("Incorrect length check for c: %d instead of %d", len(ScratchMsg.proof.c), len(clients))
	}
	ScratchMsg.proof.c = ScratchMsg.proof.c[:len(clients)-1]
	check = VerifyClientProof(ScratchMsg)
	if check {
		t.Errorf("Incorrect length check for c: %d instead of %d", len(ScratchMsg.proof.c), len(clients))
	}

	ScratchMsg = ClientMsg
	ScratchMsg.proof.r = append(ScratchMsg.proof.r, suite.Scalar().Pick(random.Stream))
	check = VerifyClientProof(ScratchMsg)
	if check {
		t.Errorf("Incorrect length check for r: %d instead of %d", len(ScratchMsg.proof.c), len(clients))
	}
	ScratchMsg.proof.r = ScratchMsg.proof.r[:2*len(clients)-1]
	check = VerifyClientProof(ScratchMsg)
	if check {
		t.Errorf("Incorrect length check for r: %d instead of %d", len(ScratchMsg.proof.c), len(clients))
	}

	ScratchMsg = ClientMsg
	ScratchMsg.proof.t = append(ScratchMsg.proof.t, suite.Point().Mul(nil, suite.Scalar().Pick(random.Stream)))
	check = VerifyClientProof(ScratchMsg)
	if check {
		t.Errorf("Incorrect length check for t: %d instead of %d", len(ScratchMsg.proof.c), len(clients))
	}
	ScratchMsg.proof.t = ScratchMsg.proof.t[:3*len(clients)-1]
	check = VerifyClientProof(ScratchMsg)
	if check {
		t.Errorf("Incorrect length check for t: %d instead of %d", len(ScratchMsg.proof.c), len(clients))
	}

	ScratchMsg = ClientMsg
	ScratchMsg.S = append(ScratchMsg.S, suite.Point().Mul(nil, suite.Scalar().Pick(random.Stream)))
	check = VerifyClientProof(ScratchMsg)
	if check {
		t.Errorf("Incorrect length check for S: %d instead of %d", len(ScratchMsg.S), len(servers)+2)
	}
	ScratchMsg.S = ScratchMsg.S[:len(servers)+1]
	check = VerifyClientProof(ScratchMsg)
	if check {
		t.Errorf("Incorrect length check for S: %d instead of %d", len(ScratchMsg.S), len(servers)+2)
	}

	//Modify the value of the generator in S[1]
	ScratchMsg = ClientMsg
	ScratchMsg.S[1] = suite.Point().Mul(nil, suite.Scalar().Pick(random.Stream))
	check = VerifyClientProof(ScratchMsg)
	if check {
		t.Errorf("Incorrect check for the generator in S[1]")
	}
	ScratchMsg.S[1] = suite.Point().Mul(nil, suite.Scalar().One())

	//Remove T0
	ScratchMsg.T0 = nil
	check = VerifyClientProof(ScratchMsg)
	if check {
		t.Errorf("Accepts a empty T0")
	}
}

func TestToBytes_ClientMessage(t *testing.T) {
	clients, servers, context, _ := generateTestContext(rand.Intn(10)+1, rand.Intn(10)+1)
	T0, S, s, _ := clients[0].CreateRequest(context)
	tproof, v, w := clients[0].GenerateProofCommitments(context, T0, s)

	//Dumb challenge generation
	cs := suite.Scalar().Pick(random.Stream)
	msg, _ := cs.MarshalBinary()
	var sigs []ServerSignature
	//Make each test server sign the challenge
	for _, server := range servers {
		sig, e := ECDSASign(server.private, msg)
		if e != nil {
			t.Errorf("Cannot sign the challenge for server %d", server.index)
		}
		sigs = append(sigs, ServerSignature{index: server.index, sig: sig})
	}
	challenge := Challenge{cs: cs, Sigs: sigs}

	//Generate the final proof
	c, r, _ := clients[0].GenerateProofResponses(context, s, &challenge, v, w)

	ClientMsg := ClientMessage{context: ContextEd25519{G: Members{X: context.G.X, Y: context.G.Y}, R: context.R, H: context.H},
		T0:    T0,
		S:     S,
		proof: ClientProof{c: *c, cs: cs, r: *r, t: *tproof}}

	//Normal execution
	data, err := ClientMsg.ToBytes()
	if err != nil {
		t.Error("Cannot convert valid Client Message to bytes")
	}
	if data == nil {
		t.Error("Data is empty for a correct Client Message")
	}
}

func TestToBytes_ClientProof(t *testing.T) {
	clients, servers, context, _ := generateTestContext(rand.Intn(10)+1, rand.Intn(10)+1)
	T0, _, s, _ := clients[0].CreateRequest(context)
	tproof, v, w := clients[0].GenerateProofCommitments(context, T0, s)

	//Dumb challenge generation
	cs := suite.Scalar().Pick(random.Stream)
	msg, _ := cs.MarshalBinary()
	var sigs []ServerSignature
	//Make each test server sign the challenge
	for _, server := range servers {
		sig, e := ECDSASign(server.private, msg)
		if e != nil {
			t.Errorf("Cannot sign the challenge for server %d", server.index)
		}
		sigs = append(sigs, ServerSignature{index: server.index, sig: sig})
	}
	challenge := Challenge{cs: cs, Sigs: sigs}

	//Generate the final proof
	c, r, _ := clients[0].GenerateProofResponses(context, s, &challenge, v, w)

	proof := ClientProof{c: *c, cs: cs, r: *r, t: *tproof}

	//Normal execution
	data, err := proof.ToBytes()
	if err != nil {
		t.Error("Cannot convert valid proof to bytes")
	}
	if data == nil {
		t.Error("Data is empty for a correct proof")
	}

}
