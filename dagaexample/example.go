package main

import (
	"dagapython"
	"fmt"
)

func main() {
	param := dagapython.GetParameters()
	fmt.Println(param.Q.BitLen())
	fmt.Println("test")
}
