package contribution

import (
	"bytes"
	"encoding/hex"
	"sync"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// ParseG1PointsNoSubgroupCheck parses a slice hex-string (with the 0x prefix) into a
// slice of G1 points.
//
// This is essentially a parallelized version of calling [parseG1PointNoSubgroupCheck]
// on each element of the slice individually.
//
// This function performs no (expensive) subgroup checks, and should only be used
// for trusted inputs.
func ParseG1PointsNoSubgroupCheck(hexStrings []string) []bls12381.G1Affine {
	numG1 := len(hexStrings)
	g1Points := make([]bls12381.G1Affine, numG1)

	var wg sync.WaitGroup
	wg.Add(numG1)
	for i := 0; i < numG1; i++ {
		go func(j int) {
			g1Point, err := parseG1PointNoSubgroupCheck(hexStrings[j])
			if err != nil {
				panic(err)
			}
			g1Points[j] = g1Point
			wg.Done()
		}(i)
	}
	wg.Wait()

	return g1Points
}

// ParseG2PointsNoSubgroupCheck parses a slice hex-string (with the 0x prefix) into a
// slice of G2 points.
//
// This is essentially a parallelized version of calling [parseG2PointNoSubgroupCheck]
// on each element of the slice individually.
//
// This function performs no (expensive) subgroup checks, and should only be used
// for trusted inputs.
func ParseG2PointsNoSubgroupCheck(hexStrings []string) []bls12381.G2Affine {
	numG2 := len(hexStrings)
	g2Points := make([]bls12381.G2Affine, numG2)

	var wg sync.WaitGroup
	wg.Add(numG2)
	for i := 0; i < numG2; i++ {
		go func(_i int) {
			g2Point, err := parseG2PointNoSubgroupCheck(hexStrings[_i])
			if err != nil {
				panic(err)
			}
			g2Points[_i] = g2Point
			wg.Done()
		}(i)
	}
	wg.Wait()

	return g2Points
}

// parseG1PointNoSubgroupCheck parses a hex-string (with the 0x prefix) into a G1 point.
//
// This function performs no (expensive) subgroup checks, and should only be used
// for trusted inputs.
func parseG1PointNoSubgroupCheck(hexString string) (bls12381.G1Affine, error) {
	byts, err := hex.DecodeString(trim0xPrefix(hexString))
	if err != nil {
		return bls12381.G1Affine{}, err
	}

	var point bls12381.G1Affine
	noSubgroupCheck := bls12381.NoSubgroupChecks()
	d := bls12381.NewDecoder(bytes.NewReader(byts), noSubgroupCheck)

	return point, d.Decode(&point)
}

// parseG2PointNoSubgroupCheck parses a hex-string (with the 0x prefix) into a G2 point.
//
// This function performs no (expensive) subgroup checks, and should only be used
// for trusted inputs.
func parseG2PointNoSubgroupCheck(hexString string) (bls12381.G2Affine, error) {
	byts, err := hex.DecodeString(trim0xPrefix(hexString))
	if err != nil {
		return bls12381.G2Affine{}, err
	}

	var point bls12381.G2Affine
	noSubgroupCheck := bls12381.NoSubgroupChecks()
	d := bls12381.NewDecoder(bytes.NewReader(byts), noSubgroupCheck)

	return point, d.Decode(&point)
}

// trim0xPrefix removes the "0x" from a hex-string.
func trim0xPrefix(hexString string) string {
	// Check that we are trimming off 0x
	if hexString[0:2] != "0x" {
		panic("hex string is not prefixed with 0x")
	}
	return hexString[2:]
}
