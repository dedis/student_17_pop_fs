package dagapython

import (
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
	err = ECDSAVerify(suite.Point().Mul(nil, servers[0].Private), msg, commit.Sig.sig)
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
