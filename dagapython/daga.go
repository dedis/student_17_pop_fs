package dagapython

import (
	"fmt"

	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/ed25519"
	"gopkg.in/dedis/crypto.v0/sign"
)

/*Members contains the list of client's (X) and server's (Y) public keys*/
type Members struct {
	X []abstract.Point
	Y []abstract.Point
}

/*ContextEd25519 holds all the context elements for DAGA with the ed25519 curve
group is the curve
R is the server's commitments
H is the client's per-round generators*/
type ContextEd25519 struct {
	G Members
	R []abstract.Point
	H []abstract.Point
}

var suite = ed25519.NewAES128SHA256Ed25519(false)

/*Sign gnerates a Schnorr signature*/
func Sign(priv abstract.Scalar, msg []byte) (s []byte, err error) {
	s, err = sign.Schnorr(suite, priv, msg)
	if err != nil {
		return nil, fmt.Errorf("Error in the signature generation")
	}
	return s, nil
}

/*Verify checks if a Schnorr signature is valid*/
func Verify(public abstract.Point, msg, sig []byte) (err error) {
	err = sign.VerifySchnorr(suite, public, msg, sig)
	return err
}
