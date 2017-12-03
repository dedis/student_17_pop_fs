package dagapython

import (
	"math/rand"
	"testing"

	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
)

func TestECDSASign(t *testing.T) {
	priv := suite.Scalar().Pick(random.Stream)
	sig, err := ECDSASign(priv, []byte("Test String"))
	if err != nil || sig == nil {
		t.Error("Cannot execute signature")
	}
}

func TestECDSAVerify(t *testing.T) {
	//Correct signature
	priv := suite.Scalar().Pick(random.Stream)
	msg := []byte("Test String")
	sig, _ := ECDSASign(priv, msg)

	check := ECDSAVerify(suite.Point().Mul(nil, priv), msg, sig)
	if check != nil {
		t.Error("Cannot verify signatures")
	}

	//Incorrect message
	var fake []byte
	copy(fake, msg)
	fake = append(fake, []byte("A")...)
	check = ECDSAVerify(suite.Point().Mul(nil, priv), fake, sig)
	if check == nil {
		t.Error("Wrong check: Message edited")
	}

	//Signature modification
	newsig := append([]byte("A"), sig...)
	newsig = newsig[:len(sig)]
	check = ECDSAVerify(suite.Point().Mul(nil, priv), fake, sig)
	if check == nil {
		t.Error("Wrong check: signature changed")
	}
}

func TestToBytes(t *testing.T) {
	c := rand.Intn(10) + 1
	s := rand.Intn(10) + 1
	_, _, context, _ := generateTestContext(c, s)
	data, err := context.ToBytes()
	if err != nil || data == nil || len(data) == 0 {
		t.Error("Cannot convert valid context to bytes")
	}
}

func TestPointArrayToBytes(t *testing.T) {
	length := rand.Intn(10) + 1
	var Points []abstract.Point
	for i := 0; i < length; i++ {
		Points = append(Points, suite.Point().Mul(nil, suite.Scalar().Pick(random.Stream)))
	}
	data, err := PointArrayToBytes(&Points)
	if err != nil || data == nil || len(data) == 0 {
		t.Error("Cannot convert Point Array to bytes")
	}
}

func TestScalarArrayToBytes(t *testing.T) {
	length := rand.Intn(10) + 1
	var Scalars []abstract.Scalar
	for i := 0; i < length; i++ {
		Scalars = append(Scalars, suite.Scalar().Pick(random.Stream))
	}
	data, err := ScalarArrayToBytes(&Scalars)
	if err != nil || data == nil || len(data) == 0 {
		t.Error("Cannot convert Scalar Array to bytes")
	}
}
