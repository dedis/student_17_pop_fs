package daga

import (
	"encoding/binary"
	"errors"
	"github.com/lbarman/prifi/config"
	prifinet "github.com/lbarman/prifi/net"
	"math/rand"
	"net"
	"strconv"
)

func (p *RelayProtocol) Start() error {
	p.relaySetup()
	return nil
}

func (p *RelayProtocol) HandleMessage(msg []byte, senderConn net.Conn) error {
	return nil
}

// Relay requests trustees to run DAGA setup collectively
func (p *RelayProtocol) relaySetup() error {

	// Send the client public key roster to all trustees
	// TODO: Send the roster once to the trustees when they join. Send them new public keys when clients join.
	rosterBytes, err := config.MarshalPointsMap(p.ClientPublicKeys)
	if err != nil {
		return errors.New("Cannot marshal public key roster. " + err.Error())
	}

	msg := make([]byte, 1+len(rosterBytes))
	msg[0] = TRUSTEE_SETUP
	copy(msg[1:], rosterBytes)

	for _, trustee := range p.Trustees {
		if err := writeMessage(trustee.Conn, msg); err != nil {
			return errors.New("Cannot write to trustee " + strconv.Itoa(trustee.Id) + ". " + err.Error())
		}
	}

	// Wait until a message is received from all trustees showing the end of the setup phase
	for _, trustee := range p.Trustees {
		trusteeMsg, err := prifinet.ReadMessage(trustee.Conn)
		if err != nil {
			return errors.New("Trustee " + strconv.Itoa(trustee.Id) + " disconnected. " + err.Error())
		}
		if int(trusteeMsg[0]) != TRUSTEE_FINISHED_SETUP {
			return errors.New("Unexpected message received from trustee " + strconv.Itoa(trustee.Id) + ".")
		}
	}
	p.Initialized = true
	//trusteesFinished := 0
	//for trusteesFinished < len(trustees) {
	//	select {
	//	case newClient := <-newClientConnectionsChan:
	//		trusteesFinished += 1
	//	default:
	//		time.Sleep(100 * time.Millisecond)
	//	}
	//}
	return nil
}

func (p *RelayProtocol) AuthenticateClient(clientConn net.Conn) (prifinet.NodeRepresentation, error) {

	// Send a welcome message to the client consisting of:
	// (1) one of the trustees' IP/port addresses;
	// (2) all trustee public keys.

	addrBytes := []byte(p.TrusteeHosts[rand.Intn(len(p.TrusteeHosts))])
	addrSize := len(addrBytes)
	pkBytes, err := config.MarshalPointsMap(p.TrusteePublicKeys)
	if err != nil {
		return prifinet.NodeRepresentation{}, errors.New("Cannot marshal server public keys. " + err.Error())
	}
	pkSize := len(pkBytes)

	welcomeMsg := make([]byte, 1+addrSize+2+pkSize)
	welcomeMsg[0] = byte(addrSize)
	copy(welcomeMsg[1:addrSize+1], addrBytes)
	binary.BigEndian.PutUint16(welcomeMsg[1+addrSize:3+addrSize], uint16(pkSize))
	copy(welcomeMsg[3+addrSize:], pkBytes)

	if err := writeMessage(clientConn, welcomeMsg); err != nil {
		return prifinet.NodeRepresentation{}, errors.New("Cannot write to the relay. " + err.Error())
	}

	// Wait until the client's authentication is finished
	//clientMsg, err := prifinet.ReadMessage(clientConn)
	//if err != nil {
	//	return prifinet.NodeRepresentation{}, errors.New("Client disconnected. " + err.Error())
	//}

	// Check validity of client's linkage tag

	return prifinet.NodeRepresentation{}, nil
}
