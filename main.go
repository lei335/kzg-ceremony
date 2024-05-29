package main

import (
	"embed"
	"flag"
	"log"
	"math/big"
	"os"

	"github.com/lei335/kzg-ceremony/contribution"
)

//go:embed transcript.json
var content embed.FS

// Update the fourth trusted setup with 32768 G1Points and then write to file
func main() {
	input := flag.String("x", "", "secret number used for powers of tau")
	flag.Parse()
	x, ok := big.NewInt(0).SetString(*input, 10)
	if !ok {
		log.Fatal("input can't be converted to bigint")
	}

	jsonResult := contribution.ReadJsonFile(content)

	jsonResult.Transcripts[3].UpdatePowerOfTau(x)

	filename := "trusted_setup.json"
	_, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	jsonResult.Transcripts[3].WriteFile(filename)
}
