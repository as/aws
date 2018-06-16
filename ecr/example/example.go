package main

import (
	"fmt"
	"os"

	"github.com/as/aws/ecr"
)

func main() {
	c, err := ecr.Stats()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("%#v\nerr: %v", c, err)
}
