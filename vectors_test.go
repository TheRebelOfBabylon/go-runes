package runes_test

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/TheRebelOfBabylon/go-runes"
)

func TestVectors(t *testing.T) {
	var err error
	// open csv file
	f, err := os.Open("test_vectors.csv")
	if err != nil {
		t.Fatalf("unexpected error when opening csv file: %v", err)
	}
	fileScanner := bufio.NewScanner(f)
	fileScanner.Split(bufio.ScanLines)
	var fileLines []string
	for fileScanner.Scan() {
		fileLines = append(fileLines, fileScanner.Text())
	}
	defer f.Close()
	var vecs [][]string
	for _, line := range fileLines {
		vecs = append(vecs, strings.Split(strings.ReplaceAll(line, "\n", ""), ","))
	}
	// create master rune
	mr, err := runes.NewMasterRune(make([]byte, 16), "", "")
	if err != nil {
		t.Errorf("unexpected error when creating new rune: %v", err)
	}
	t.Logf("runestr=%s\nbase64runestr=%s", mr.String(), mr.Encode())
	var (
		rune1 *runes.Rune
		rune2 *runes.Rune
	)
	for _, vec := range vecs {
		switch vec[0] {
		case "VALID":
			t.Log(vec[1])
			rune1, err = runes.RuneFromString(vec[2])
			if err != nil {
				t.Errorf("unexpected error when parsing rune string: %v", err)
			}
			rune2, err = runes.RuneFromEncodedString(vec[3])
			if err != nil {
				t.Errorf("unexpected error when parsing encoded rune string: %v", err)
			}
			if rune1.String() != rune2.String() {
				t.Errorf("unexpected result when comparing identical runes: %s and %s", rune1.String(), rune2.String())
			}
			if !mr.IsRuneAuthorized(rune1) {
				t.Error("rune1 is not issued by master rune when it should be")
			}
			if !mr.IsRuneAuthorized(rune2) {
				t.Error("rune2 is not issued by master rune when it should be")
			}
			if len(vec) == 6 {
				if rune1.Restrictions[0][0].String() != fmt.Sprintf("=%v-%v", vec[4], vec[5]) {
					t.Errorf("unexpected first rune restriction: %s", rune1.Restrictions[0][0].String())
				}
			} else if len(vec) == 5 {
				if rune1.Restrictions[0][0].String() != fmt.Sprintf("=%v", vec[4]) {
					t.Errorf("unexpected first rune restriction: %s", rune1.Restrictions[0][0].String())
				}
			} else {
				if len(vec) != 4 {
					t.Errorf("vector contains an unexpected number of elements: %v", len(vec))
				}
				if len(rune1.Restrictions) != 0 && strings.HasPrefix(rune1.Restrictions[0][0].String(), "=") {
					t.Errorf("unexpected first restriction in rune1: %s", rune1.Restrictions[0][0].String())
				}
			}
		case "MALFORMED":
			t.Log(vec[1])
			errMsg := runes.ErrInvalidCondition.Error()
			if strings.Contains(vec[1], "unique id") || strings.Contains(vec[1], "version") {
				errMsg = "unique_id"
			}
			if _, err = runes.RuneFromString(vec[2]); !strings.Contains(err.Error(), errMsg) {
				t.Errorf("unexpected error when parsing rune string: %v", err)
			}
			if _, err = runes.RuneFromEncodedString(vec[3]); !strings.Contains(err.Error(), errMsg) {
				t.Errorf("unexpected error when parsing encoded rune string: %v", err)
			}
		case "BAD DERIVATION":
			t.Log(vec[1])
			rune1, err = runes.RuneFromString(vec[2])
			if err != nil {
				t.Errorf("unexpected error when parsing rune string: %v", err)
			}
			rune2, err = runes.RuneFromEncodedString(vec[3])
			if err != nil {
				t.Errorf("unexpected error when parsing encoded rune string: %v", err)
			}
			if rune1.String() != rune2.String() {
				t.Errorf("unexpected result when comparing rune1 to rune2: %s and %s", rune1.String(), rune2.String())
			}
			if mr.IsRuneAuthorized(rune1) {
				t.Error("rune1 is authorized by the master rune when it should not be")
			}
			if mr.IsRuneAuthorized(rune2) {
				t.Error("rune2 is authorized by the master rune when it should not be")
			}
		case "PASS":
			if len(vec) > 1 {
				variables := make(map[string]runes.Test)
				for _, v := range vec[1:] {
					parts := strings.SplitN(v, "=", -1)
					// try to parse parts[1] into an integer
					vInt, err := strconv.ParseInt(parts[1], 10, 64)
					if err == nil {
						variables[parts[0]] = runes.Test{Value: vInt, TestFunc: runes.StandardTestFunc}
					}
					variables[parts[0]] = runes.Test{Value: parts[1], TestFunc: runes.StandardTestFunc}
				}
				if err = rune1.AreRestrictionsMet(variables); err != nil {
					t.Errorf("unexpected error when testing rune restrictions: %v", err)
				}
				if err = rune2.AreRestrictionsMet(variables); err != nil {
					t.Errorf("unexpected error when testing rune restrictions: %v", err)
				}
			}
		default:
			if len(vec) > 1 {
				if vec[0] != "FAIL" {
					t.Errorf("unexpected value in vector: %v", vec[0])
				}
				variables := make(map[string]runes.Test)
				for _, v := range vec[1:] {
					parts := strings.SplitN(v, "=", -1)
					// try to parse parts[1] into an integer
					vInt, err := strconv.ParseInt(parts[1], 10, 64)
					if err == nil {
						variables[parts[0]] = runes.Test{Value: vInt, TestFunc: runes.StandardTestFunc}
					}
					variables[parts[0]] = runes.Test{Value: parts[1], TestFunc: runes.StandardTestFunc}
				}
				if err = rune1.AreRestrictionsMet(variables); err == nil {
					t.Error("expected error when testing rune restrictions and received none")
				}
				if err = rune2.AreRestrictionsMet(variables); err == nil {
					t.Error("expected error when testing rune restrictions and received none")
				}
			}
		}
	}
}
