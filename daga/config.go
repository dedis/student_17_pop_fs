/*
Package config contains the cryptographic primitives that are used by the PriFi library.
 */
package daga

import (
	"encoding/binary"
	"errors"
	"github.com/BurntSushi/toml"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/base64"
	"gopkg.in/dedis/crypto.v0/cipher"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/crypto.v0/suites"
	"gopkg.in/dedis/crypto.v0/util"
	"io/ioutil"
	"os"
	"os/user"
	"runtime"
	"strconv"
)

func ConfigDir(name string) (string, error) {

	var homedir string
	if runtime.GOOS == "windows" {
		usr, err := user.Current()
		if err != nil {
			return "", err
		}
		homedir = usr.HomeDir
	} else {
		homedir = os.Getenv("HOME")
	}
	confDir := homedir + "/." + name
	return confDir, nil
}

// Loads a node's config data from a folder.
// The folder must contain a TOML-format .config file and a .sec file containing the node's private key.
func (c *NodeConfig) Load(name string) error {

	dir, err := ConfigDir(name)
	if err != nil {
		return err
	}

	// Read the config file if it exists
	filename := dir + "/config.tml"
	_, err = toml.DecodeFile(filename, &c.nodePubConfig)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	// Lookup the appropriate cipher suite for this public key.
	suite := suites.All()[c.Suite]
	if suite == nil {
		return errors.New("Unsupported ciphersuite '" + c.Suite + "'")
	}

	// Read the private key file
	secFilename := dir + "/" + c.PubId + ".sec"
	secFile, err := os.Open(secFilename)
	if err != nil {
		return err
	}
	defer secFile.Close()

	if err := suite.Read(secFile, &c.PrivateKey); err != nil {
		return err
	}

	// Reconstruct and verify the public key
	c.PublicKey = suite.Point().Mul(nil, c.PrivateKey)
	if getPublicStringIdentifier(suite, c.PublicKey) != c.PubId {
		return errors.New("Secret does not yield public key " + c.PubId)
	}

	// Load public key roster if it exists
	rosterFilename := dir + "/roster"
	if _, err := os.Stat(rosterFilename); err == nil {

		var rosterBytes []byte
		if rosterBytes, err = ioutil.ReadFile(rosterFilename); err != nil {
			return err
		}
		if c.PublicKeyRoster, err = UnmarshalPointsMap(suite, rosterBytes); err != nil {
			return errors.New("Cannot unmarshal node's public key roster. " + err.Error())
		}
	}

	return nil
}

// Saves a node's config data into a folder
// The folder will contain a TOML-format .config file and a .sec file containing the node's private key.
func (c *NodeConfig) Save(appName string) error {

	dir, err := ConfigDir(appName)
	if err != nil {
		return err
	}

	// Delete the config directory if it already exists
	if err := os.RemoveAll(dir); err != nil {
		return err
	}

	// Create the config directory
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	// Delete the file if it exists
	filename := dir + "/config.tml"
	if _, err := os.Stat(filename); err == nil {
		os.Remove(filename)
	}

	// Create a new config file
	file, err := os.Create(filename)
	if err != nil {
		return err
	}

	// Save the config file
	enc := toml.NewEncoder(file)
	if err := enc.Encode(c.nodePubConfig); err != nil {
		return err
	}
	defer file.Close()

	// Save the private key into a sec file
	secFilename := dir + "/" + c.PubId + ".sec"
	r := util.Replacer{}
	if err := r.Open(secFilename); err != nil {
		return err
	}
	defer r.Abort()

	// Write the secret key
	suite := suites.All()[c.Suite]
	if err := suite.Write(r.File, &c.PrivateKey); err != nil {
		return err
	}

	if err := r.Commit(); err != nil {
		return err
	}
	return nil
}

// Generates a public/private key pair
func (c *NodeConfig) GenKeyPair(suite abstract.Suite, random cipher.Stream) {

	c.Suite = suite.String()
	c.PrivateKey = suite.Scalar().Pick(random)
	c.PublicKey = suite.Point().Mul(nil, c.PrivateKey)
	c.PubId = getPublicStringIdentifier(suite, c.PublicKey)
}

func getPublicStringIdentifier(suite abstract.Suite, publicKey abstract.Point) string {
	buf, _ := publicKey.MarshalBinary()
	hash := abstract.Sum(suite, buf)
	return base64.RawURLEncoding.EncodeToString(hash)
}

// Generates a config folder for each node: clients, servers, and a relay
// For clients and servers, the folder will contain a TOML-formatted config file
// and a binary secret key file. For the relay, the folder will also contain a binary file
// that contains a dictionary of (pubId, public key)'s for all nodes.
func GenerateConfig(nClients int, nTrustees int, authMethod int, suite abstract.Suite) error {

	nodesConfig := make([]NodeConfig, nClients+nTrustees)

	// Create trustees' config files
	id := int(1)
	for i := 0; id < nTrustees+1; id++ {

		nodeConfig := NodeConfig{}
		nodeConfig.Id = id
		nodeConfig.Name = "prifi-trustee-" + strconv.Itoa(i)
		nodeConfig.Type = NODE_TYPE_TRUSTEE
		nodeConfig.AuthMethod = authMethod
		nodeConfig.GenKeyPair(suite, random.Stream)
		if err := nodeConfig.Save(nodeConfig.Name); err != nil {
			return err
		}
		nodesConfig[i] = nodeConfig
		i++
	}

	// Create clients' config files
	for i := 0; id < nClients+nTrustees+1; id++ {

		nodeConfig := NodeConfig{}
		nodeConfig.Id = id
		nodeConfig.Name = "prifi-client-" + strconv.Itoa(i)
		nodeConfig.Type = NODE_TYPE_CLIENT
		nodeConfig.AuthMethod = authMethod
		nodeConfig.GenKeyPair(suite, random.Stream)
		if err := nodeConfig.Save(nodeConfig.Name); err != nil {
			return err
		}
		nodesConfig[nTrustees+i] = nodeConfig
		i++
	}

	// Create relay's config file
	relayConfig := NodeConfig{}
	relayConfig.GenKeyPair(suite, random.Stream)
	relayConfig.Id = 0 // Relay's id is always 0
	relayConfig.Name = "prifi-relay"
	relayConfig.Type = NODE_TYPE_RELAY
	relayConfig.AuthMethod = authMethod
	relayConfig.NodesInfo = make([]NodeInfo, len(nodesConfig))

	for i := 0; i < len(nodesConfig); i++ {
		relayConfig.NodesInfo[i] = nodesConfig[i].NodeInfo
	}

	if err := relayConfig.Save(relayConfig.Name); err != nil {
		return err
	}

	// Create the public roster which is a map of (node ID, public key)'s for all nodes
	dir, err := ConfigDir(relayConfig.Name)
	if err != nil {
		return err
	}

	pubs := make(map[int]abstract.Point)
	for _, nodeConfig := range nodesConfig {
		pubs[nodeConfig.Id] = nodeConfig.PublicKey
	}

	rosterFile, err := os.Create(dir + "/roster")
	if err != nil {
		return err
	}
	defer rosterFile.Close()

	rosterBytes, _ := MarshalPointsMap(pubs)
	if _, err := rosterFile.Write(rosterBytes); err != nil {
		return err
	}
	return nil
}

// Marshals a map of (nodeId, Point) into a byte arrays
func MarshalPointsMap(pointsMap map[int]abstract.Point) ([]byte, error) {

	var arr []byte

	// Marshal number of entries in the map
	numEntries := make([]byte, 4)
	binary.BigEndian.PutUint32(numEntries, uint32(len(pointsMap)))
	arr = append(arr, numEntries...)

	// Marshal each entry
	for k, v := range pointsMap {

		keyBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(keyBytes, uint32(k))
		arr = append(arr, keyBytes...) // Key

		valBytes, err := v.MarshalBinary()
		if err != nil {
			return []byte{}, err
		}
		valBytesLength := make([]byte, 2)
		binary.BigEndian.PutUint16(valBytesLength, uint16(len(valBytes)))

		arr = append(arr, valBytesLength...) // Value length
		arr = append(arr, valBytes...)       // Value
	}
	return arr, nil
}

func UnmarshalPointsMap(suite abstract.Suite, arr []byte) (map[int]abstract.Point, error) {

	pointsMap := make(map[int]abstract.Point)
	numEntries := int(binary.BigEndian.Uint32(arr[0:4]))

	i := 4
	for j := 0; j < numEntries; j++ {

		key := int(binary.BigEndian.Uint32(arr[i : i+4]))

		valBytesLen := int(binary.BigEndian.Uint16(arr[i+4 : i+6]))
		valBytes := arr[i+6 : i+6+valBytesLen]

		point := suite.Point()
		if err := point.UnmarshalBinary(valBytes); err != nil {
			return map[int]abstract.Point{}, err
		}
		pointsMap[key] = point
		i += 6 + valBytesLen
	}
	return pointsMap, nil
}
