package main

import (
	"crypto/sha512"
	"fmt"
	"io"

	"gopkg.in/dedis/crypto.v0/ed25519"
)

func main() {
	//param := dagapython.GetParameters()
	//fmt.Println(param.Q.BitLen())
	fmt.Println("test")
	hash := sha512.New()
	hash.Reset()
	var writer io.Writer = hash
	var C = ed25519.Curve{}
	C.Point().Mul(nil, C.Scalar().One()).MarshalTo(writer)
	h1 := hash.Sum(nil)
	hash.Reset()
	data, _ := C.Point().Mul(nil, C.Scalar().One()).MarshalBinary()
	h2 := hash.Sum(data)
	fmt.Println("h1")
	fmt.Printf("%x\n", h1)
	fmt.Println("Point")
	fmt.Printf("%x\n", data)
	fmt.Println("h2")
	fmt.Printf("%x\n", h2)
	hash.Reset()
	fmt.Println("emmpty hash")
	fmt.Printf("%x\n", hash.Sum(nil))
}
