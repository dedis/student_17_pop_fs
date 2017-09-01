package daga

import (
	"encoding/binary"
	"net"

	"gopkg.in/dedis/crypto.v0/abstract"
)

const (
	NODE_TYPE_RELAY   = "Relay"
	NODE_TYPE_TRUSTEE = "Trustee"
	NODE_TYPE_CLIENT  = "Client"
)

// Node's personal information
type NodeInfo struct {
	Id    int    // Node id
	Name  string // Node name
	Type  string // Node type
	Suite string // Cipher suite name
	PubId string // My public key identifier. Used to validate the secret key file
}

// Node's public configuration information
// This type is marshaled into the node's .config file
type nodePubConfig struct {
	NodeInfo              // My public info
	NodesInfo  []NodeInfo // Other nodes' public info
	AuthMethod int        // Authentication method
}

// Node's configuration
// This type is marshaled into the node's config folder
type NodeConfig struct {
	nodePubConfig // Node's information

	PublicKey  abstract.Point
	PrivateKey abstract.Scalar

	PublicKeyRoster map[int]abstract.Point // Other nodes' public keys
}

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
			return CryptoSuite.Point(), err
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
