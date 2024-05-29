// Update powersOfTau in transcript.json,
// and split transcript.json into 4 small files based on 4 sets of trusted-setup
package contribution

import (
	"embed"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/big"
	"os"

	bls12381Fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// // ScalarsPerBlob is the number of serialized scalars in a blob.
// const (
// 	ScalarsPerBlob1 = 4096
// 	ScalarsPerBlob2 = 8192
// 	ScalarsPerBlob3 = 16384
// 	ScalarsPerBlob4 = 32768
// )

// JSONResult is a struct used for serializing the transcripts from/to JSON format.
type JSONResult struct {
	Transcripts []Transcript `json:"transcripts"`
}

type Transcript struct {
	NumG1Powers int         `json:"numG1Powers"`
	NumG2Powers int         `json:"numG2Powers"`
	Powers      PowersOfTau `json:"powersOfTau"`
}

type PowersOfTau struct {
	G1Powers []G1CompressedHexStr `json:"G1Powers"`
	G2Powers []G2CompressedHexStr `json:"G2Powers"`
}

type JSONTrustedSetup struct {
	SetupG1 []G1CompressedHexStr `json:"g1_monomial"`
	SetupG2 []G2CompressedHexStr `json:"g2_monomial"`
}

// G1CompressedHexStr is a hex-string (with the 0x prefix) of a compressed G1 point.
type G1CompressedHexStr = string

// G2CompressedHexStr is a hex-string (with the 0x prefix) of a compressed G2 point.
type G2CompressedHexStr = string

// Read transcript.json and return pointer of JSONResult struct.
// embed does not support "../" syntax, so it needs to be passed in from a file in the
// same directory as the target file "transcript.json"
func ReadJsonFile(fs embed.FS) *JSONResult {
	config, err := fs.ReadFile("transcript.json")
	if err != nil {
		log.Fatal(err)
	}

	params := new(JSONResult)
	if err = json.Unmarshal(config, params); err != nil {
		log.Fatal(err)
	}

	return params
}

// Update powersOfTau: 1*G1Powers[0],x*G1Powers[1],x^2*G1Powers[2],...;1*G2Powers[0],x*G2Powers[1],x^2*G2Powers[2],...
func (t *Transcript) UpdatePowerOfTau(x *big.Int) {
	G1Points := ParseG1PointsNoSubgroupCheck(t.Powers.G1Powers)
	G2Points := ParseG2PointsNoSubgroupCheck(t.Powers.G2Powers)

	xPower := big.NewInt(1)
	var (
		compressedG1 [48]byte
		compressedG2 [96]byte
	)

	for i := 0; i < t.NumG1Powers; i++ {
		G1Points[i].ScalarMultiplication(&G1Points[i], xPower)

		compressedG1 = G1Points[i].Bytes()
		t.Powers.G1Powers[i] = "0x" + hex.EncodeToString(compressedG1[:])

		if i < t.NumG2Powers {
			G2Points[i].ScalarMultiplication(&G2Points[i], xPower)

			compressedG2 = G2Points[i].Bytes()
			t.Powers.G2Powers[i] = "0x" + hex.EncodeToString(compressedG2[:])
		}
		xPower.Mul(xPower, x).Mod(xPower, bls12381Fr.Modulus())
	}
}

// Write to file, serialize the transcript to JSON format.
func (t *Transcript) WriteFile(filePath string) error {
	setup := &JSONTrustedSetup{}
	setup.SetupG1 = t.Powers.G1Powers
	setup.SetupG2 = t.Powers.G2Powers
	data, err := json.Marshal(setup)
	if err != nil {
		log.Fatal(err)
	}

	// write file with read-only permission
	return os.WriteFile(filePath, data, 0444)
}
