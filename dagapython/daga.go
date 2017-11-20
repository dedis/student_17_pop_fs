package dagapython

import (
	"crypto/rand"

	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/ed25519"
	"gopkg.in/dedis/crypto.v0/sign"
)

/*Group contains the list of client's (X) and server's (Y) public keys*/
type Group struct {
	X []abstract.Point
	Y []abstract.Point
}

/*ContextEd25519 holds all the context elements for DAGA with the ed25519 curve
group is the curve
R is the server's commitments
H is the client's per-round generators*/
type ContextEd25519 struct {
	G Group
	R []abstract.Point
	H []abstract.Point
	C ed25519.Curve
}

/*GenerateRandomBytes returns securely generated random bytes.
It will return an error if the system's secure random
number generator fails to function correctly, in which
case the caller should not continue.
https://elithrar.github.io/article/generating-secure-random-numbers-crypto-rand/ */
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}
	return b, nil
}

/*RandReader struct used to implement the io.Reader interface for GenerateRandomBytes*/
type RandReader struct{}

/*Read function for GenerateRandomBytes*/
func (r RandReader) Read(b []byte) (int, error) {
	b, err := GenerateRandomBytes(len(b))
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

/*Sign uses gnerates a Schnorr signature*/
func Sign(priv abstract.Scalar, msg []byte) (s []byte, err error) {
	suite := ed25519.NewAES128SHA256Ed25519(false)
	s, err = sign.Schnorr(suite, priv, msg)
	if err != nil {
		panic("Error in the signature generation")
	}
	return s, err
}

/*Verify check if a Schnorr signature is valid*/
func Verify(public abstract.Point, msg, sig []byte) (err error) {
	suite := ed25519.NewAES128SHA256Ed25519(false)
	err = sign.VerifySchnorr(suite, public, msg, sig)
	return err
}
