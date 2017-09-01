package daga

import (
	"errors"
	"github.com/dedis/crypto/abstract"
	"github.com/lbarman/prifi/config"
	prifinet "github.com/lbarman/prifi/net"
	"net"
	"strconv"
)

func (p *TrusteeProtocol) HandleMessage(msg []byte, senderConn net.Conn) error {

	switch msg[0] {
	case TRUSTEE_SETUP:
		err := p.trusteeSetup(msg[1:])
		return err

	case CLIENT_CONTEXT_REQ:
		err := p.trusteeNewClient(senderConn)
		return err
	}
	return nil
}

// Trustee runs DAGA setup collectively with other trustees
func (p *TrusteeProtocol) trusteeSetup(msg []byte) error {

	// Extract public key roster from the message
	publicKeyRoster, err := config.UnmarshalPointsMap(config.CryptoSuite, msg[1:])
	if err != nil {
		return errors.New("Cannot unmarshall public key roster. " + err.Error())
	}
	p.publicKeyRoster = publicKeyRoster

	// Generate a secret r_j and the commitment R_j = g^r_j
	commits := make(map[int]abstract.Point, len(p.trustees)) // Trustees' commitments
	rand := config.CryptoSuite.Cipher(nil)
	g := config.CryptoSuite.Point().Base()
	r := config.CryptoSuite.Scalar().Pick(rand) // Random secret
	commits[p.trusteeId] = config.CryptoSuite.Point().Mul(g, r)

	// Broadcast the commitment to other trustees
	Rb, _ := commits[p.trusteeId].MarshalBinary()
	prifinet.NUnicastMessageToNodes(p.trustees, Rb)

	// Receive and collect commitments of other trustees
	for _, trustee := range p.trustees {

		// TODO: Reading from multiple trustees can be done in parallel using a goroutine.
		commitBinary, err := prifinet.ReadMessage(trustee.Conn)
		if err == nil {
			// TODO: If a trustee disconnects, we should rerun the setup.
			return errors.New("Cannot read from the trustee " + strconv.Itoa(trustee.Id) + ". " + err.Error())
		}

		commitment := config.CryptoSuite.Point()
		err = commitment.UnmarshalBinary(commitBinary)
		if err == nil {
			return errors.New("Cannot unmarshal trustee " + strconv.Itoa(trustee.Id) + " commitment. " + err.Error())
		}
		commits[trustee.Id] = commitment
	}
	p.trusteeCommitments = commits

	// Generate a group generator h_i = H(i, commits) for each client i
	p.clientGenerators = make(map[int]abstract.Point, len(p.publicKeyRoster))
	for clientId, _ := range p.publicKeyRoster {
		p.clientGenerators[clientId], err = computeClientGroupGenerator(config.CryptoSuite, clientId, commits)
		if err != nil {
			return errors.New("Cannot compute client generator. " + err.Error())
		}
	}
	return nil
}

// Trustee sends an authentication context (trustee commitments) to the client
func (p *TrusteeProtocol) trusteeNewClient(clientConn net.Conn) error {

	commitBytes, err := config.MarshalPointsMap(p.trusteeCommitments)
	if err != nil {
		return errors.New("Cannot marshal trustee commitments. " + err.Error())
	}

	if err := writeMessage(clientConn, commitBytes); err != nil {
		return errors.New("Cannot write to the client. " + err.Error())
	}
	return nil
}
