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

//Suite exports the cryptographic interface to external packages
var Suite = ed25519.NewAES128SHA256Ed25519(false)
var suite = ed25519.NewAES128SHA256Ed25519(false)

/*ECDSASign gnerates a Schnorr signature*/
func ECDSASign(priv abstract.Scalar, msg []byte) (s []byte, err error) {
	//Input checks
	if priv == nil {
		return nil, fmt.Errorf("Empty private key")
	}
	if msg == nil || len(msg) == 0 {
		return nil, fmt.Errorf("Empty message")
	}

	s, err = sign.Schnorr(suite, priv, msg)
	if err != nil {
		return nil, fmt.Errorf("Error in the signature generation")
	}
	return s, nil
}

/*ECDSAVerify checks if a Schnorr signature is valid*/
func ECDSAVerify(public abstract.Point, msg, sig []byte) (err error) {
	//Input checks
	if public == nil {
		return fmt.Errorf("Empty public key")
	}
	if msg == nil || len(msg) == 0 {
		return fmt.Errorf("Empty message")
	}
	if sig == nil || len(sig) == 0 {
		return fmt.Errorf("Empty signature")
	}

	err = sign.VerifySchnorr(suite, public, msg, sig)
	return err
}

/*ToBytes is a utility functton to convert a ContextEd25519 into []byte, used in signatures*/
func (context *ContextEd25519) ToBytes() (data []byte, err error) {
	temp, e := PointArrayToBytes(&context.G.X)
	if e != nil {
		return nil, fmt.Errorf("Error in X: %s", e)
	}
	data = append(data, temp...)

	temp, e = PointArrayToBytes(&context.G.Y)
	if e != nil {
		return nil, fmt.Errorf("Error in Y: %s", e)
	}
	data = append(data, temp...)

	temp, e = PointArrayToBytes(&context.H)
	if e != nil {
		return nil, fmt.Errorf("Error in H: %s", e)
	}
	data = append(data, temp...)

	temp, e = PointArrayToBytes(&context.R)
	if e != nil {
		return nil, fmt.Errorf("Error in R: %s", e)
	}
	data = append(data, temp...)

	return data, nil
}

/*PointArrayToBytes is a utility function to convert a abstract.Point array into []byte, used in signatures*/
func PointArrayToBytes(array *[]abstract.Point) (data []byte, err error) {
	for _, p := range *array {
		temp, e := p.MarshalBinary()
		if e != nil {
			return nil, fmt.Errorf("Error in S: %s", e)
		}
		data = append(data, temp...)
	}
	return data, nil
}

/*ScalarArrayToBytes is a utility function to convert a abstract.Scalar array into []byte, used in signatures*/
func ScalarArrayToBytes(array *[]abstract.Scalar) (data []byte, err error) {
	for _, s := range *array {
		temp, e := s.MarshalBinary()
		if e != nil {
			return nil, fmt.Errorf("Error in S: %s", e)
		}
		data = append(data, temp...)
	}
	return data, nil
}
