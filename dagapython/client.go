package dagapython

import (
	"crypto/sha512"

	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
)

/*CreateRequest generates the authentication request to be sent to an arbitrary server*/
func CreateRequest(c ContextEd25519, id int, priv abstract.Scalar) []byte {
	//Step 1: generate ephemeral DH keys
	z := c.C.Scalar().Pick(random.Stream)
	Z := c.C.Point().Mul(nil, z)

	//Step 2: Generate shared secrets with the servers
	s := make([][sha512.Size]byte, len(c.G.Y))
	for i := 0; i < len(c.G.Y); i++ {
		temp, err := c.C.Point().Mul(c.G.Y[i], z).MarshalBinary()
		if err != nil {
			panic("Error in multiply")
		}
		s[i] = sha512.Sum512(temp)
	}
	//Step 3: initial linkage tag and commitments
	//Computes the value of the exponent for the initial linkage tag
	exp := c.C.Scalar().One()
	for i := 0; i < len(c.G.Y); i++ {
		// TODO: Correct this error
		exp.Mul(exp, c.C.Scalar().SetBytes(s[i]))
	}
	temp, err := c.C.Point().Mul(c.H[id], exp).MarshalBinary()
	if err != nil {
		panic("Error in T0")
	}
	T0 := temp
	//Computes the commitments
	S := make([][]byte, len(c.G.Y))
	exp = c.C.Scalar().One()
	for i := 0; i < len(c.G.Y)+1; i++ {
		temp, err := c.C.Point().Mul(nil, exp).MarshalBinary()
		if err != nil {
			panic("Error in commitments")
		}
		S[i] = temp
		// TODO: Correct this error
		exp.Mul(exp, c.C.Scalar().SetBytes(s[i]))
	}
	sExp := exp

	//Step 4: Generate the proof

	return msg
}

// TODO:
func GenerateProofCommitments(C ContextEd25519, sExp abstract.Scalar, id int) (t [][]byte, w []abstract.Scalar) {

}

// TODO:
func GenerateProofResponses() (c, r []abstract.Scalar) {

}
