package dagapython

import (
	"fmt"
	"strconv"

	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
)

/*Server is used to store the server's private key and index.
All the server's methods are attached to it */
type Server struct {
	Private abstract.Scalar
	index   int
}

/*Commitment stores the index of the server, the commitment value and the signature for the commitment*/
type Commitment struct {
	commit abstract.Point
	Sig    ServerSignature
}

/*ServerSignature stores a signature created by a server and the server's index*/
type ServerSignature struct {
	index int
	sig   []byte
}

/*Challenge stores the collectively generated challenge and the signatures of the servers*/
type Challenge struct {
	cs   abstract.Scalar
	Sigs []ServerSignature
}

/*GenerateCommitment creates the commitment and its opening for the distributed challenge generation*/
func (server *Server) GenerateCommitment(context ContextEd25519) (commit Commitment, opening abstract.Scalar) {
	opening = context.C.Scalar().Pick(random.Stream)
	com := context.C.Point().Mul(nil, opening)
	msg, err := com.MarshalBinary()
	if err != nil {
		panic("Error in conversion of commit")
	}
	sig, err := Sign(server.Private, msg)
	if err != nil {
		panic("Error in commit signature generation")
	}
	return Commitment{Sig: ServerSignature{index: server.index, sig: sig}, commit: com}, opening
}

/*VerifyCommitmentSignature verifies that all the commitments are valid and correctly signed*/
func (server *Server) VerifyCommitmentSignature(context ContextEd25519, commits []Commitment) (err error) {
	for i, com := range commits {
		if i != com.Sig.index {
			return fmt.Errorf("Wrong index")
		}
		//TODO: How to check that a point is on the curve?

		//Covnert the commitment and verify the signature
		msg, e := com.commit.MarshalBinary()
		if e != nil {
			return fmt.Errorf("Error in conversion of commit for verification")
		}
		err = Verify(context.G.Y[i], msg, com.Sig.sig)
		if err != nil {
			return err
		}
	}
	return nil
}

/*CheckOpenings verifies each opening and returns the computed challenge*/
func (server *Server) CheckOpenings(context ContextEd25519, commits []Commitment, openings []abstract.Scalar) (cs abstract.Scalar, err error) {
	if len(commits) != len(openings) {
		return nil, fmt.Errorf("Length does not match")
	}
	cs = context.C.Scalar().Zero()
	for i := 0; i < len(commits); i++ {
		c := context.C.Point().Mul(nil, openings[i])
		if !commits[i].commit.Equal(c) {
			return nil, fmt.Errorf("Mismatch for server " + strconv.Itoa(i))
		}
		cs = context.C.Scalar().Add(cs, openings[i])
	}
	return cs, nil
}

/*CheckChallengeSignatures verifies that all the previous servers computed the same challenges and that their signatures are valid
It also adds the server's signature to the list if it the round-robin is not completed (the challenge has not yet made it back to the leader)*/
// TODO: Should I use *Challenge to be able to modify it without having to return it?
func (server *Server) CheckChallengeSignatures(context ContextEd25519, cs abstract.Scalar, challenge Challenge) (newChallenge Challenge, err error) {
	//Checks that the challenge values match
	if !cs.Equal(challenge.cs) {
		// TODO: Why nil does not work?
		//return nil, fmt.Errorf("Challenge values does not match")
		panic("Challenge values does not match")
	}
	//Check the signatures
	msg, e := challenge.cs.MarshalBinary()
	if e != nil {
		panic("Error in challenge conversion")
	}
	for _, sig := range challenge.Sigs {
		e = Verify(context.G.Y[sig.index], msg, sig.sig)
		if e != nil {
			panic(e)
		}
	}
	//Add the server's signature to the list if it is not the last one
	if len(challenge.Sigs) == len(context.G.Y) {
		return challenge, nil
	}
	sig, e := Sign(server.Private, msg)
	if e != nil {
		panic(e)
	}
	newChallenge = Challenge{Sigs: append(challenge.Sigs, ServerSignature{index: server.index, sig: sig}), cs: challenge.cs}

	return newChallenge, nil
}
