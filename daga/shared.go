package daga

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/nist"
)

// Used to make sure everybody has the same version of the software. must be updated manually
const LLD_PROTOCOL_VERSION = 3

// Number of times to retry connecting to a node
const NUM_RETRY_CONNECT = 3

// Sets the crypto suite used
var CryptoSuite = nist.NewAES128SHA256P256()

type NodeRepresentation struct {
	Id        int
	Conn      net.Conn //classical TCP connection
	Connected bool
	PublicKey abstract.Point
}

func NUnicastMessageToNodes(nodes []NodeRepresentation, message []byte) {

	for i := 0; i < len(nodes); i++ {
		if nodes[i].Connected {
			err := WriteMessage(nodes[i].Conn, message)

			if err != nil {
				fmt.Println("Could not n*unicast to conn", i, "gonna set it to disconnected.")
				nodes[i].Connected = false
			}
		}
	}
}

func ReadMessage(conn net.Conn) ([]byte, error) {

	header := make([]byte, 6)
	emptyMessage := make([]byte, 0)

	//read header
	n, err := io.ReadFull(conn, header)

	if err != nil {
		return emptyMessage, err
	}

	if n != 6 {
		return emptyMessage, errors.New("Couldn't read the full 6 header bytes, only read " + strconv.Itoa(n))
	}

	//parse header
	version := int(binary.BigEndian.Uint16(header[0:2]))
	bodySize := int(binary.BigEndian.Uint32(header[2:6]))

	if version != LLD_PROTOCOL_VERSION {

		return emptyMessage, errors.New("Read a message with protocol " + strconv.Itoa(version) + " bytes, but our version is " + strconv.Itoa(LLD_PROTOCOL_VERSION) + ".")
	}

	//read body
	body := make([]byte, bodySize)
	n2, err2 := io.ReadFull(conn, body)

	if err2 != nil {
		return emptyMessage, err2
	}

	if n2 != bodySize {
		return emptyMessage, errors.New("Couldn't read the full" + strconv.Itoa(bodySize) + " body bytes, only read " + strconv.Itoa(n2))
	}

	return body, nil
}

func WriteMessage(conn net.Conn, message []byte) error {

	length := len(message)

	//compose new message
	buffer := make([]byte, length+6)
	binary.BigEndian.PutUint16(buffer[0:2], uint16(LLD_PROTOCOL_VERSION))
	binary.BigEndian.PutUint32(buffer[2:6], uint32(length))
	copy(buffer[6:], message)

	n, err := conn.Write(buffer)

	if n < length+6 {
		return errors.New("Couldn't write the full" + strconv.Itoa(length+6) + " bytes, only wrote " + strconv.Itoa(n))
	}

	if err != nil {
		return err
	}

	return nil
}
