package daga

import (
	"encoding/binary"
	"errors"
	"github.com/dedis/crypto/abstract"
	"github.com/lbarman/prifi/config"
	prifinet "github.com/lbarman/prifi/net"
	"net"
	"strconv"
)

// Client participates in authentication process
func ClientAuthentication(relayConn net.Conn, clientId int, privateKey abstract.Scalar) error {

	// Receive a welcome message from the relay
	welcomeMsg, err := prifinet.ReadMessage(relayConn)
	if err != nil {
		return errors.New("Relay disconnected. " + err.Error())
	}

	// Extract a trustee host address from the message
	addrSize := int(welcomeMsg[0])
	trusteeAddr := string(welcomeMsg[1 : addrSize+1])

	// Extract trustee public keys from the message
	pkSize := int(binary.BigEndian.Uint16(welcomeMsg[1+addrSize : 3+addrSize]))
	serverPublicKeys, err := config.UnmarshalPointsMap(config.CryptoSuite, welcomeMsg[3+addrSize:3+addrSize+pkSize])
	if err != nil {
		return errors.New("Cannot unmarshal trustee public keys." + err.Error())
	}

	// Connect to the trustee
	trusteeConn, err := net.Dial("tcp", trusteeAddr)
	if err != nil {
		return errors.New("Client cannot connect to the trustee. " + err.Error())
	}

	// Request authentication context from the trustee
	reqMsg := make([]byte, 1)
	reqMsg[0] = CLIENT_CONTEXT_REQ
	if err := writeMessage(trusteeConn, reqMsg); err != nil {
		return errors.New("Client cannot write to the trustee. " + err.Error())
	}

	// Receive trustee commitments from the trustee
	commitBytes, err := prifinet.ReadMessage(relayConn)
	if err != nil {
		return errors.New("Trustee disconnected. " + err.Error())
	}
	trusteeCommits, err := config.UnmarshalPointsMap(config.CryptoSuite, commitBytes)
	if err != nil {
		return errors.New("Cannot unmarshal trustee commitments. " + err.Error())
	}

	// Calculate my per-round generator h_i
	h, err := computeClientGroupGenerator(config.CryptoSuite, clientId, trusteeCommits)
	if err != nil {
		return err
	}

	// Generate an ephemeral key pair (z, Z)
	rand := config.CryptoSuite.Cipher(nil)
	base := config.CryptoSuite.Point().Base()
	z := config.CryptoSuite.Scalar().Pick(rand) // Ephemeral private key
	//Z := config.CryptoSuite.Point().Mul(base, z) // Ephemeral public key

	// Compute the initial linkage tag and client's commitments (one commitment for each trustee)
	sProduct := config.CryptoSuite.Scalar().One()
	S := make(map[int]abstract.Point, len(serverPublicKeys)) // Client's commitments

	for j, _ := range serverPublicKeys {

		exp := config.CryptoSuite.Point().Mul(serverPublicKeys[j], z)
		s := hashPoint(config.CryptoSuite, exp)               // s_j = H(Y_j^z_i), Y_j is trustee j public key
		S[j] = config.CryptoSuite.Point().Mul(base, sProduct) // Client commitment: S_j = g^{s_1 * ... * s_j}
		sProduct = config.CryptoSuite.Scalar().Mul(sProduct, s)
	}
	initialTag := config.CryptoSuite.Point().Mul(h, sProduct) // T_0 = h_i^{s_1 * ... * s_m}

	// Send the linkage tag to the first trustee
	initTagBytes, err := initialTag.MarshalBinary()
	if err != nil {
		return errors.New("Client " + strconv.Itoa(clientId) + " cannot marshal initial tag. " + err.Error())
	}
	if err := writeMessage(trusteeConn, initTagBytes); err != nil {
		return errors.New("Cannot write to the client. " + err.Error())
	}

	// TODO: Run the interactive ZKP protocol of Camenisch and Stadler with the trustee to prove that:
	// TODO: (1) The client has correctly computed the linkage tag;
	// TODO: (2) He knows one of the groups private keys.
	// TODO: See Section 1.3.7 of DAGA chapter

	// Receive the final linkage tag from the trustee
	finalTagBytes, err := prifinet.ReadMessage(trusteeConn)
	if err != nil {
		return errors.New("Trustee disconnected. " + err.Error())
	}
	finalTag := config.CryptoSuite.Point()
	finalTag.UnmarshalBinary(finalTagBytes)

	return nil
}
