package daga

import (
	"encoding/binary"
	"github.com/dedis/crypto/abstract"
	"github.com/lbarman/prifi/config"
	"net"
)

func writeMessage(conn net.Conn, msg []byte) error {

	// Add protocol type to the message
	authMsg := make([]byte, len(msg)+1)
	authMsg[0] = PROTOCOL_TYPE_DAGA
	copy(authMsg[1:], msg)

	if err := writeMessage(conn, authMsg); err != nil {
		return err
	}
	return nil
}

// Hashes a point by converting it from the point (base) group to a secret (exponent) group
func hashPoint(suite abstract.Suite, p abstract.Point) abstract.Scalar {
	pb, _ := p.MarshalBinary()
	c := suite.Cipher(pb)
	return suite.Scalar().Pick(c)
}

// Computes a client's per-round generator (h_i)
func computeClientGroupGenerator(suite abstract.Suite, clientId int,
	serverCommits map[int]abstract.Point) (abstract.Point, error) {

	// Embed clientId and commitments into a byte array to be hashed
	hashInput := make([]byte, 0)
	for _, commit := range serverCommits {
		cb, err := commit.MarshalBinary()
		if err != nil {
			return config.CryptoSuite.Point(), err
		}
		hashInput = append(hashInput, cb...)
	}

	idb := make([]byte, 4)
	binary.BigEndian.PutUint32(idb, uint32(clientId))
	hashInput = append(hashInput, idb...)

	// Hash the byte array into a base point
	return hashBytes(suite, hashInput, []byte("fixed")), nil
}

// Hashes a sequence of bytes into a point on an elliptic curve
func hashBytes(suite abstract.Suite, input []byte, seed []byte) abstract.Point {

	// TODO: Is this the most efficient way to hash a sequence of bytes into a Point?
	rand := suite.Cipher(seed)
	p, rem := suite.Point().Pick(input, rand)

	for len(rem) > 0 {
		var prem abstract.Point
		prem, rem = suite.Point().Pick(rem, rand)
		suite.Point().Add(p, prem)
	}
	return p
}
