package dagapython

import (
	"crypto/sha512"
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
	r       abstract.Scalar //Per round secret
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

/*ServerMessage stores the message sent by a server to one or many others*/
type ServerMessage struct {
	request ClientMessage
	tags    []abstract.Point
	proofs  []ServerProof
	indexes []int
}

/*ServerProof stores a server proof of his computations*/
type ServerProof struct {
	t1 abstract.Point
	t2 abstract.Point
	t3 abstract.Point
	c  []byte
	r1 abstract.Scalar
	r2 abstract.Scalar
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

/*ServerProtocol runs the server part of DAGA upon receiving a message from either a server or a client*/
func (server *Server) ServerProtocol(context ContextEd25519, msg ServerMessage) (ServerMessage, error) {
	//Step 1
	//Verify that the message is correctly formed
	if !ValidateClientMessage(msg.request) {
		return ServerMessage{}, fmt.Errorf("Invalid client's request")
	}
	if len(msg.indexes) != len(msg.proofs) || len(msg.proofs) != len(msg.tags) {
		return ServerMessage{}, fmt.Errorf("Invalid message")
	}
	// TODO: Add signature checking before processing the proofs
	if !VerifyClientProof(msg.request) {
		return ServerMessage{}, fmt.Errorf("Invalid client's proof")
	}

	if len(msg.proofs) != 0 {
		for _, p := range msg.proofs {
			var valid bool
			if p.t3 == nil && p.r2 == nil {
				valid = VerifyMisbehavingProof(p)
			} else {
				valid = VerifyServerProof(p)
			}
			if !valid {
				return ServerMessage{}, fmt.Errorf("Invalid server proof")
			}
		}
	}

	//Step 2: Verify the correct behaviour of the client
	temp, err := context.C.Point().Mul(msg.request.S[0], server.Private).MarshalBinary()
	if err != nil {
		panic("Error in shared secrets")
	}
	hash := sha512.Sum512(temp)
	s := context.C.Scalar().SetBytes(hash[:])
	var T abstract.Point
	var proof ServerProof
	//Detect a misbehaving client and generate the elements of the server's message accordingly
	if !msg.request.S[server.index+1].Equal(context.C.Point().Mul(msg.request.S[server.index], s)) {
		T = context.C.Point().Null()
		proof = server.GenerateMisbehavingProof()
	} else {
		inv := context.C.Scalar().Inv(s)
		exp := context.C.Scalar().Mul(server.r, inv)
		T = context.C.Point().Mul(msg.tags[len(msg.tags)-1], exp)
		proof = server.GenerateServerProof()
	}
	//Step 4: Form the new message
	out := ServerMessage{
		request: msg.request,
		tags:    append(msg.tags, T),
		proofs:  append(msg.proofs, proof),
		indexes: append(msg.indexes, server.index),
	}

	return out, nil
}

func (server *Server) GenerateServerProof() (proof ServerProof) {
	return ServerProof{}
}

func VerifyServerProof(proof ServerProof) bool {
	return false
}

func (server *Server) GenerateMisbehavingProof() (proof ServerProof) {
	return ServerProof{}
}

func VerifyMisbehavingProof(proof ServerProof) bool {
	return false
}
