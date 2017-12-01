package dagapython

import (
	"crypto/sha512"
	"encoding/binary"
	"io"

	"gopkg.in/dedis/crypto.v0/abstract"
)

/*GenerateClientGenerator generates a per-round generator for a given client*/
func GenerateClientGenerator(index int, commits *[]abstract.Point) (gen *[]abstract.Point) {

	hasher := sha512.New()
	var writer io.Writer = hasher
	idb := make([]byte, 4)
	binary.BigEndian.PutUint32(idb, uint32(index))
	writer.Write(idb)
	for _, R := range *commits {
		R.MarshalTo(writer)
	}
	hash := hasher.Sum(nil)
	// TODO: How to map a hash to a point on the curve?
	return nil
}
