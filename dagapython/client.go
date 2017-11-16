package dagapython

import (
	"crypto/sha512"

	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
)

/*Client is used to store the client's private key and index.
All the client's methods are attached to it */
type Client struct {
	Private abstract.Scalar
	index   int
}

/*CreateRequest generates the elements for the authentication request (T0, S) and the generation of the client's proof (s)*/
func (client *Client) CreateRequest(context ContextEd25519) (T0 abstract.Point, S []abstract.Point, s abstract.Scalar) {
	//Step 1: generate ephemeral DH keys
	z := context.C.Scalar().Pick(random.Stream)
	Z := context.C.Point().Mul(nil, z)

	//Step 2: Generate shared secrets with the servers
	shared := make([][]byte, len(context.G.Y))
	for i := 0; i < len(context.G.Y); i++ {
		temp, err := context.C.Point().Mul(context.G.Y[i], z).MarshalBinary()
		if err != nil {
			panic("Error in shared secrets")
		}
		hash := sha512.Sum512(temp)
		shared[i] = hash[:]
	}

	//Step 3: initial linkage tag and commitments
	//Computes the value of the exponent for the initial linkage tag
	exp := context.C.Scalar().One()
	for i := 0; i < len(context.G.Y); i++ {
		exp.Mul(exp, context.C.Scalar().SetBytes(shared[i]))
	}
	T0 = context.C.Point().Mul(context.H[client.index], exp)

	//Computes the commitments
	// TODO: SLice of Scalar
	S = make([]abstract.Point, len(context.G.Y))
	exp = context.C.Scalar().One()
	for i := 0; i < len(context.G.Y)+1; i++ {
		S[i] = context.C.Point().Mul(nil, exp)
		exp.Mul(exp, context.C.Scalar().SetBytes(shared[i]))
	}
	s = exp

	//Add the client's ephemeral public key to the commitments
	/*Prepend taken from comment at
	https://codingair.wordpress.com/2014/07/18/go-appendprepend-item-into-slice/ */
	S = append(S, nil)
	copy(S[1:], S)
	S[0] = Z

	return T0, S, s
}

// TODO:
func (client *Client) GenerateProofCommitments(C ContextEd25519, s abstract.Scalar) (t []abstract.Point, w []abstract.Scalar) {
	return nil, nil
}

// TODO:
func (client *Client) GenerateProofResponses(C ContextEd25519, s abstract.Scalar, cs abstract.Scalar, t []abstract.Point, w []abstract.Scalar) (c, r []abstract.Scalar) {
	return nil, nil
}
