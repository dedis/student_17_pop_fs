package daga

import (
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"io"

	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
)

/*GenerateClientGenerator generates a per-round generator for a given client*/
func GenerateClientGenerator(index int, commits *[]abstract.Point) (gen abstract.Point, err error) {
	if index < 0 {
		return nil, fmt.Errorf("Wrond index: %d", index)
	}
	if len(*commits) <= 0 {
		return nil, fmt.Errorf("Wrong commits:\n%v", commits)
	}

	hasher := sha512.New()
	var writer io.Writer = hasher
	idb := make([]byte, 4)
	binary.BigEndian.PutUint32(idb, uint32(index))
	writer.Write(idb)
	for _, R := range *commits {
		R.MarshalTo(writer)
	}
	hash := hasher.Sum(nil)
	rand := suite.Cipher(hash)
	gen, _ = suite.Point().Pick(nil, rand)
	return
}

func generateTestContext(c, s int) (clients []Client, servers []Server, context *ContextEd25519, err error) {
	context = &ContextEd25519{}
	if c <= 0 {
		return nil, nil, nil, fmt.Errorf("Invalid number of client asked: %d", c)
	}

	if s <= 0 {
		return nil, nil, nil, fmt.Errorf("Invalid number of client asked: %d", s)
	}

	//Generates s servers
	for i := 0; i < s; i++ {
		new := Server{index: i, private: suite.Scalar().Pick(random.Stream)}
		context.G.Y = append(context.G.Y, suite.Point().Mul(nil, new.private))
		servers = append(servers, new)
	}

	//Generates the per-round secrets for the ServerSignature
	for i, serv := range servers {
		context.R = append(context.R, serv.GenerateNewRoundSecret())
		servers[i] = serv
	}

	//Generates c clients with their per-round generators
	for i := 0; i < c; i++ {
		new := Client{index: i, private: suite.Scalar().Pick(random.Stream)}
		context.G.X = append(context.G.X, suite.Point().Mul(nil, new.private))
		clients = append(clients, new)

		temp, err := GenerateClientGenerator(i, &context.R)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("Error in client's generators:\n%s", err)
		}

		context.H = append(context.H, temp)
	}

	return clients, servers, context, nil
}
