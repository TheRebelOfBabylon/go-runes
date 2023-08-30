package runes_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/TheRebelOfBabylon/go-runes"
)

// endShastreamSimle is a simplified version of endShastream
func endShastreamSimple(length int) []byte {
	stream := []byte{0x80}
	for (length+len(stream)+8)%64 != 0 {
		stream = append(stream, 0x00)
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(length*8))
	return append(stream, buf...)
}

// checkAuthSha manually creates the authcode with restrictions
func checkAuthSha(secret []byte, restrictions []runes.Restriction) []byte {
	stream := secret[:]
	stream = append(stream, endShastreamSimple(len(stream))...)
	for _, restriction := range restrictions {
		encodedRes := []byte(restriction.String())
		stream = append(stream, encodedRes...)
		stream = append(stream, endShastreamSimple(len(encodedRes))...)
	}
	h := sha256.New()
	_, _ = h.Write(stream)
	marshaler := h.(encoding.BinaryMarshaler)
	state, _ := marshaler.MarshalBinary()
	return state[4 : 4+h.Size()]
}

// TestRuneAuth
func TestRuneAuth(t *testing.T) {
	// create master rune
	secret := make([]byte, 16)
	masterRune, err := runes.NewMasterRune(secret, "", "")
	if err != nil {
		t.Errorf("unexpected error when creating master rune: %v", err)
	}
	// check its authcode
	if !bytes.Equal(checkAuthSha(secret, nil), masterRune.Authcode()) {
		t.Errorf("unexpected result when comparing master rune authcode: %x and %x", checkAuthSha(secret, nil), masterRune.Authcode())
	}
	// create a new rune from master rune authcode
	newRune, err := runes.RuneFromAuthcode(masterRune.Authcode(), nil)
	if err != nil {
		t.Errorf("unexpected error when creating a new rune %v", err)
	}
	// compare both authcodes
	if !masterRune.IsRuneAuthorized(newRune) {
		t.Error("new rune does not pass authorization check")
	}
	// add a restriction to the master rune
	newRestriction := runes.Restriction{&runes.Alternative{Field: "f1", Condition: "=", Value: "v1"}}
	err = masterRune.AddRestriction(newRestriction)
	if err != nil {
		t.Errorf("unexpected error when adding restriction to master rune: %v", err)
	}
	// validate new master rune authcode
	if !bytes.Equal(checkAuthSha(secret, []runes.Restriction{newRestriction}), masterRune.Authcode()) {
		t.Errorf("unexpected result when comparing master rune authcode: %x and %x", checkAuthSha(secret, []runes.Restriction{newRestriction}), masterRune.Authcode())
	}
	// create a new rune without restrictions from current master rune authcode
	newRuneNoRes, err := runes.RuneFromAuthcode(masterRune.Authcode(), nil)
	if err != nil {
		t.Errorf("unexpected error when creating new rune from authcode: %v", err)
	}
	// check if the new rune passes the auth check. It shouldn't
	if masterRune.IsRuneAuthorized(newRuneNoRes) {
		t.Error("unexpected result when checking if the new rune has been authorized by the master rune")
	}
	// create a new rune without restrictions from current master rune authcode
	newRuneWithRes, err := runes.RuneFromAuthcode(masterRune.Authcode(), []runes.Restriction{newRestriction})
	if err != nil {
		t.Errorf("unexpected error when creating new rune from authcode: %v", err)
	}
	// check if this new rune with the proper restriction passes the auth check
	if !masterRune.IsRuneAuthorized(newRuneWithRes) {
		t.Errorf("unexpected result when checking if the new rune has the proper restricitons and authcode: %s and %s", newRuneWithRes.String(), masterRune.String())
	}
	// create a long restriciton
	longRestriction := runes.Restriction{&runes.Alternative{Field: strings.Repeat("f", 32), Condition: "=", Value: strings.Repeat("v1", 64)}}
	err = masterRune.AddRestriction(longRestriction)
	if err != nil {
		t.Errorf("unexpected error when adding long restriction to master rune: %v", err)
	}
	// manually check the master rune authcode
	if !bytes.Equal(checkAuthSha(secret, []runes.Restriction{newRestriction, longRestriction}), masterRune.Authcode()) {
		t.Error("unexpected result when manually checking the master rune authcode")
	}
	newRune, err = runes.RuneFromAuthcode(masterRune.Authcode(), []runes.Restriction{newRestriction})
	if err != nil {
		t.Errorf("unexpected error when creating new rune: %v", err)
	}
	// ensure the new rune is invalid
	if masterRune.IsRuneAuthorized(newRune) {
		t.Errorf("unexpected result when checking if the new rune has the proper restricitons and authcode: %s and %s", newRuneWithRes.String(), masterRune.String())
	}
	newRune, err = runes.RuneFromAuthcode(masterRune.Authcode(), []runes.Restriction{longRestriction})
	if err != nil {
		t.Errorf("unexpected error when creating new rune: %v", err)
	}
	// ensure the new rune is invalid
	if masterRune.IsRuneAuthorized(newRune) {
		t.Errorf("unexpected result when checking if the new rune has the proper restricitons and authcode: %s and %s", newRuneWithRes.String(), masterRune.String())
	}
	newRune, err = runes.RuneFromAuthcode(masterRune.Authcode(), []runes.Restriction{longRestriction, newRestriction})
	if err != nil {
		t.Errorf("unexpected error when creating new rune: %v", err)
	}
	// ensure the new rune is invalid. Order matters
	if masterRune.IsRuneAuthorized(newRune) {
		t.Errorf("unexpected result when checking if the new rune has the proper restricitons and authcode: %s and %s", newRuneWithRes.String(), masterRune.String())
	}
	newRune, err = runes.RuneFromAuthcode(masterRune.Authcode(), []runes.Restriction{newRestriction, longRestriction})
	if err != nil {
		t.Errorf("unexpected error when creating new rune: %v", err)
	}
	// ensure the new rune is valid. Order matters
	if !masterRune.IsRuneAuthorized(newRune) {
		t.Errorf("unexpected result when checking if the new rune has the proper restricitons and authcode: %s and %s", newRuneWithRes.String(), masterRune.String())
	}
	// old runes are still valid. This stuff is magic
	if !masterRune.IsRuneAuthorized(newRuneWithRes) {
		t.Errorf("unexpected result when checking if the new rune has the proper restricitons and authcode: %s and %s", newRuneWithRes.String(), masterRune.String())
	}
}

func TestNewRuneWithId(t *testing.T) {
	secret := make([]byte, 32)
	r, err := runes.NewMasterRune(secret, "123456789", "")
	if err != nil {
		t.Errorf("unexpected error creating rune: %v", err)
	}
	t.Logf("rune: %s", r.String())
	t.Logf("authbase: %x", r.Authcode())
	t.Logf("encoded: %s", r.Encode())
}

func TestNewRuneWithRestrictions(t *testing.T) {
	secret := make([]byte, 32)
	r, err := runes.NewMasterRune(secret, "123456789", "")
	if err != nil {
		t.Errorf("unexpected error creating rune: %v", err)
	}
	restriction, err := runes.RestrictionFromString("time < 2", false)
	if err != nil {
		t.Errorf("unexpected error creating restriction: %v", err)
	}
	err = r.AddRestriction(restriction)
	if err != nil {
		t.Errorf("unexpected error adding restriction to rune: %v", err)
	}
	t.Logf("rune: %s", r.String())
	t.Logf("authbase: %x", r.Authcode())
	t.Logf("encoded: %s", r.Encode())
}

func TestNewRuneNoRestrictions(t *testing.T) {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	r, err := runes.NewMasterRune(secret, "", "")
	if err != nil {
		t.Errorf("unexpected error creating new rune: %v", err)
	}
	t.Logf("rune: %s", r.String())
	t.Logf("authbase: %x", r.Authcode())
	t.Logf("encoded: %s", r.Encode())
}

func TestRuneFromEncodedStringNoRestrictions(t *testing.T) {
	r, err := runes.RuneFromEncodedString("KNb4MXVG7BwY8Zwuqh8L9SEiQEGhWs1VzHvVwMvNnYY=")
	if err != nil {
		t.Errorf("unexpected error decoding rune: %v", err)
	}
	if fmt.Sprintf("%x", r.Authcode()) != "28d6f8317546ec1c18f19c2eaa1f0bf521224041a15acd55cc7bd5c0cbcd9d86" {
		t.Errorf("unexpected authcode: %x", r.Authcode())
	}
	t.Logf("rune: %s", r.String())
	t.Logf("authbase: %x", r.Authcode())
	if len(r.Restrictions) != 0 {
		t.Errorf("unexpected restrictions in rune: %v", r.Restrictions)
	}
}

type encodedStrTestCases struct {
	encodedStr   string
	authcode     string
	restrictions []string
}

var (
	testCases = []encodedStrTestCases{
		{
			"rEhxxJJWN2NvUJ1LCEmE9rwhyK-GV16h6Cx270LIDPdpZD0xMjM0NTY3ODk=",
			"ac4871c4925637636f509d4b084984f6bc21c8af86575ea1e82c76ef42c80cf7",
			[]string{"id=123456789"},
		},
		{
			"n-fwIGCj2Xaq3ws_q1nTIezNsUs3jk3wo222OdJAlaNpZD0xMjM0NTY3ODkmdGltZTwy",
			"9fe7f02060a3d976aadf0b3fab59d321eccdb14b378e4df0a36db639d24095a3",
			[]string{"id=123456789", "time<2"},
		},
	}
)

func TestRuneFromEncodedString(t *testing.T) {
	for _, testCase := range testCases {
		r, err := runes.RuneFromEncodedString(testCase.encodedStr)
		if err != nil {
			t.Errorf("unexpected error decoding rune: %v", err)
		}
		if fmt.Sprintf("%x", r.Authcode()) != testCase.authcode {
			t.Errorf("unexpected authcode: %x", r.Authcode())
		}
		t.Logf("rune: %s", r.String())
		if len(r.Restrictions) != len(testCase.restrictions) {
			t.Errorf("Unexpected number of restrictions in rune %v", len(r.Restrictions))
		}
		for _, res := range r.Restrictions {
			t.Log(res.String())
		}
	}
}

func TestRuneFromEncodedStringThenAddRestriction(t *testing.T) {
	r, err := runes.RuneFromEncodedString("rEhxxJJWN2NvUJ1LCEmE9rwhyK-GV16h6Cx270LIDPdpZD0xMjM0NTY3ODk=")
	if err != nil {
		t.Errorf("unexpected error decoding rune: %v", err)
	}
	if fmt.Sprintf("%x", r.Authcode()) != "ac4871c4925637636f509d4b084984f6bc21c8af86575ea1e82c76ef42c80cf7" {
		t.Errorf("unexpected authcode: %x", r.Authcode())
	}
	t.Logf("rune: %s", r.String())
	if len(r.Restrictions) != 1 {
		t.Errorf("Unexpected number of restrictions in rune %v", len(r.Restrictions))
	}
	// Now add restriction
	restriction, err := runes.RestrictionFromString("time < 2", false)
	if err != nil {
		t.Errorf("Unexpected error when creating restriction: %v", err)
	}
	err = r.AddRestriction(restriction)
	if err != nil {
		t.Errorf("Unexpected error when adding restriction: %v", err)
	}
	if fmt.Sprintf("%x", r.Authcode()) != "9fe7f02060a3d976aadf0b3fab59d321eccdb14b378e4df0a36db639d24095a3" {
		t.Errorf("unexpected authcode: %x", r.Authcode())
	}
	if r.Encode() != "n-fwIGCj2Xaq3ws_q1nTIezNsUs3jk3wo222OdJAlaNpZD0xMjM0NTY3ODkmdGltZTwy" {
		t.Errorf("unexpected encoded rune: %s", r.Encode())
	}
	if len(r.Restrictions) != 2 {
		t.Errorf("Unexpected number of restrictions in rune %v", len(r.Restrictions))
	}
	t.Logf("new rune: %s", r.String())
}

// TestRuneAlternatives tests that alternatives are interpreted as expected
func TestRuneAlternatives(t *testing.T) {
	alt, err := runes.NewAlternative("f1", "!", "", false)
	if err != nil {
		t.Errorf("unexpected error when creating alternative: %v", err)
	}
	err = alt.Test(make(map[string]runes.Test))
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"1", runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrFieldIsPresent) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f2": {"1", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}

	alt, err = runes.NewAlternative("f1", "=", "1", false)
	if err != nil {
		t.Errorf("unexpected error when creating alternative: %v", err)
	}
	err = alt.Test(make(map[string]runes.Test))
	if !errors.Is(err, runes.ErrMissingField) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"1", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"01", runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrForbiddenValue) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"10", runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrForbiddenValue) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"010", runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrForbiddenValue) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"10101", runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrForbiddenValue) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}

	alt, err = runes.NewAlternative("f1", "/", "1", false)
	if err != nil {
		t.Errorf("unexpected error when creating alternative: %v", err)
	}
	err = alt.Test(make(map[string]runes.Test))
	if !errors.Is(err, runes.ErrMissingField) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"1", runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrForbiddenValue) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"01", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"10", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"010", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"10101", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}

	alt, err = runes.NewAlternative("f1", "$", "1", false)
	if err != nil {
		t.Errorf("unexpected error when creating alternative: %v", err)
	}
	err = alt.Test(make(map[string]runes.Test))
	if !errors.Is(err, runes.ErrMissingField) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"1", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"01", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"10", runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrInvalidValueSuffix) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"010", runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrInvalidValueSuffix) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"10101", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}

	alt, err = runes.NewAlternative("f1", "^", "1", false)
	if err != nil {
		t.Errorf("unexpected error when creating alternative: %v", err)
	}
	err = alt.Test(make(map[string]runes.Test))
	if !errors.Is(err, runes.ErrMissingField) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"1", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"01", runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrInvalidValuePrefix) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"10", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"010", runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrInvalidValuePrefix) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"10101", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}

	alt, err = runes.NewAlternative("f1", "~", "1", false)
	if err != nil {
		t.Errorf("unexpected error when creating alternative: %v", err)
	}
	err = alt.Test(make(map[string]runes.Test))
	if !errors.Is(err, runes.ErrMissingField) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"1", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"01", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"10", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"010", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"10101", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"020", runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrValueDoesntContain) {
		t.Errorf("unexpected error when testing alterntive: %v", err)
	}

	alt, err = runes.NewAlternative("f1", "<", "1", false)
	if err != nil {
		t.Errorf("unexpected error when creating alternative: %v", err)
	}
	err = alt.Test(make(map[string]runes.Test))
	if !errors.Is(err, runes.ErrMissingField) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"1", runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrCondValueTypeMismatch) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {1, runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrValueTooLarge) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {01, runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrValueTooLarge) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {10, runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrValueTooLarge) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {010, runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrValueTooLarge) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {10101, runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrValueTooLarge) {
		t.Errorf("unexpected error when testing alterntive: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {020, runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrValueTooLarge) {
		t.Errorf("unexpected error when testing alterntive: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {0, runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alterntive: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"x", runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrCondValueTypeMismatch) {
		t.Errorf("unexpected error when testing alterntive: %v", err)
	}

	alt, err = runes.NewAlternative("f1", "<", "x", false)
	if err != nil {
		t.Errorf("unexpected error when creating alternative: %v", err)
	}
	err = alt.Test(make(map[string]runes.Test))
	if !errors.Is(err, runes.ErrMissingField) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {1, runes.StandardTestFunc}})
	if !errors.Is(err, strconv.ErrSyntax) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}

	alt, err = runes.NewAlternative("f1", ">", "1", false)
	if err != nil {
		t.Errorf("unexpected error when creating alternative: %v", err)
	}
	err = alt.Test(make(map[string]runes.Test))
	if !errors.Is(err, runes.ErrMissingField) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"1", runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrCondValueTypeMismatch) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {1, runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrValueTooSmall) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {01, runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrValueTooSmall) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {10, runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {010, runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {10101, runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alterntive: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {020, runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alterntive: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {0, runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrValueTooSmall) {
		t.Errorf("unexpected error when testing alterntive: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"x", runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrCondValueTypeMismatch) {
		t.Errorf("unexpected error when testing alterntive: %v", err)
	}

	alt, err = runes.NewAlternative("f1", ">", "x", false)
	if err != nil {
		t.Errorf("unexpected error when creating alternative: %v", err)
	}
	err = alt.Test(make(map[string]runes.Test))
	if !errors.Is(err, runes.ErrMissingField) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {1, runes.StandardTestFunc}})
	if !errors.Is(err, strconv.ErrSyntax) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}

	alt, err = runes.NewAlternative("f1", "{", "1", false)
	if err != nil {
		t.Errorf("unexpected error when creating alternative: %v", err)
	}
	err = alt.Test(make(map[string]runes.Test))
	if !errors.Is(err, runes.ErrMissingField) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"1", runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrWrongLexicOrder) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"01", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"10", runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrWrongLexicOrder) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"010", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"10101", runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrWrongLexicOrder) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"020", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alterntive: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"0", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}

	alt, err = runes.NewAlternative("f1", "}", "1", false)
	if err != nil {
		t.Errorf("unexpected error when creating alternative: %v", err)
	}
	err = alt.Test(make(map[string]runes.Test))
	if !errors.Is(err, runes.ErrMissingField) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"1", runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrWrongLexicOrder) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"01", runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrWrongLexicOrder) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"10", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"010", runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrWrongLexicOrder) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"10101", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"020", runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrWrongLexicOrder) {
		t.Errorf("unexpected error when testing alterntive: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"0", runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrWrongLexicOrder) {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}

	alt, err = runes.NewAlternative("f1", "#", "1", false)
	if err != nil {
		t.Errorf("unexpected error when creating alternative: %v", err)
	}
	err = alt.Test(make(map[string]runes.Test))
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"1", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"01", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"10", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"010", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"10101", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"020", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alterntive: %v", err)
	}
	err = alt.Test(map[string]runes.Test{"f1": {"0", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing alternative: %v", err)
	}
}

// TestRuneRestriction tests a restriction with more than one alternative for expected behaviour
func TestRuneRestriction(t *testing.T) {
	altOne, err := runes.NewAlternative("f1", "!", "", false)
	if err != nil {
		t.Errorf("unexpected error when creating alternative: %v", err)
	}
	altTwo, err := runes.NewAlternative("f2", "=", "2", false)
	if err != nil {
		t.Errorf("unexpected error when creating alternative: %v", err)
	}

	// either can be true
	restr := runes.Restriction{altOne, altTwo}
	err = restr.Test(make(map[string]runes.Test))
	if err != nil {
		t.Errorf("unexpected error when testing restriction: %v", err)
	}
	err = restr.Test(map[string]runes.Test{"f1": {"1", runes.StandardTestFunc}, "f2": {3, runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrFieldIsPresent) && !errors.Is(err, runes.ErrForbiddenValue) {
		t.Errorf("unexpected error when testing restriction: %v", err)
	}
	err = restr.Test(map[string]runes.Test{"f2": {1, runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing restriction: %v", err)
	}
	err = restr.Test(map[string]runes.Test{"f2": {2, runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing restriction: %v", err)
	}
	err = restr.Test(map[string]runes.Test{"f2": {"2", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing restriction: %v", err)
	}
}

// TestRuneRestrictions checks to see if a rune with multiple restrictions with one or more alternatives behaves expectedly
func TestRuneRestrictions(t *testing.T) {
	altOne, err := runes.NewAlternative("f1", "!", "", false)
	if err != nil {
		t.Errorf("unexpected error when creating alternative: %v", err)
	}
	altTwo, err := runes.NewAlternative("f2", "=", "2", false)
	if err != nil {
		t.Errorf("unexpected error when creating alternative: %v", err)
	}

	newRune, err := runes.NewMasterRune(make([]byte, 32), "", "")
	if err != nil {
		t.Errorf("unexpected error when creating rune: %v", err)
	}
	err = newRune.AddRestriction(runes.Restriction{altOne, altTwo})
	if err != nil {
		t.Errorf("unexpected error when adding restriction to rune: %v", err)
	}
	err = newRune.AreRestrictionsMet(make(map[string]runes.Test))
	if err != nil {
		t.Errorf("unexpected error when testing rune: %v", err)
	}
	err = newRune.AreRestrictionsMet(map[string]runes.Test{"f1": {"1", runes.StandardTestFunc}, "f2": {3, runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrFieldIsPresent) && !errors.Is(err, runes.ErrForbiddenValue) {
		t.Errorf("unexpected error when testing rune: %v", err)
	}
	err = newRune.AreRestrictionsMet(map[string]runes.Test{"f1": {"1", runes.StandardTestFunc}, "f2": {2, runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing rune: %v", err)
	}
	err = newRune.AreRestrictionsMet(map[string]runes.Test{"f2": {"1", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing rune: %v", err)
	}
	err = newRune.AreRestrictionsMet(map[string]runes.Test{"f2": {"2", runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing rune: %v", err)
	}

	altThree, err := runes.NewAlternative("f3", ">", "2", false)
	if err != nil {
		t.Errorf("unexpected error when creating alternative: %v", err)
	}
	err = newRune.AddRestriction(runes.Restriction{altThree})
	if err != nil {
		t.Errorf("unexpected error when adding restriction to rune: %v", err)
	}
	err = newRune.AreRestrictionsMet(make(map[string]runes.Test))
	if !errors.Is(err, runes.ErrMissingField) {
		t.Errorf("unexpected error when testing rune: %v", err)
	}
	err = newRune.AreRestrictionsMet(map[string]runes.Test{"f1": {"1", runes.StandardTestFunc}, "f2": {3, runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrFieldIsPresent) && !errors.Is(err, runes.ErrForbiddenValue) {
		t.Errorf("unexpected error when testing rune: %v", err)
	}
	err = newRune.AreRestrictionsMet(map[string]runes.Test{"f1": {"1", runes.StandardTestFunc}, "f2": {2, runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrMissingField) {
		t.Errorf("unexpected error when testing rune: %v", err)
	}
	err = newRune.AreRestrictionsMet(map[string]runes.Test{"f2": {"1", runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrMissingField) {
		t.Errorf("unexpected error when testing rune: %v", err)
	}
	err = newRune.AreRestrictionsMet(map[string]runes.Test{"f2": {"2", runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrMissingField) {
		t.Errorf("unexpected error when testing rune: %v", err)
	}
	err = newRune.AreRestrictionsMet(map[string]runes.Test{"f3": {2, runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrValueTooSmall) {
		t.Errorf("unexpected error when testing rune: %v", err)
	}
	err = newRune.AreRestrictionsMet(map[string]runes.Test{"f3": {3, runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing rune: %v", err)
	}
	err = newRune.AreRestrictionsMet(map[string]runes.Test{"f1": {"1", runes.StandardTestFunc}, "f2": {"x", runes.StandardTestFunc}, "f3": {3, runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrFieldIsPresent) && !errors.Is(err, runes.ErrForbiddenValue) {
		t.Errorf("unexpected error when testing rune: %v", err)
	}
	err = newRune.AreRestrictionsMet(map[string]runes.Test{"f2": {"1", runes.StandardTestFunc}, "f3": {2, runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrValueTooSmall) {
		t.Errorf("unexpected error when testing rune: %v", err)
	}
	err = newRune.AreRestrictionsMet(map[string]runes.Test{"f2": {"2", runes.StandardTestFunc}, "f3": {2, runes.StandardTestFunc}})
	if !errors.Is(err, runes.ErrValueTooSmall) {
		t.Errorf("unexpected error when testing rune: %v", err)
	}
	err = newRune.AreRestrictionsMet(map[string]runes.Test{"f2": {"1", runes.StandardTestFunc}, "f3": {3, runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing rune: %v", err)
	}
	err = newRune.AreRestrictionsMet(map[string]runes.Test{"f2": {"2", runes.StandardTestFunc}, "f3": {4, runes.StandardTestFunc}})
	if err != nil {
		t.Errorf("unexpected error when testing rune: %v", err)
	}
}

// TestRuneString whether we can create a rune and then successfully parse it
func TestRuneString(t *testing.T) {
	altOne, err := runes.NewAlternative("f1", "!", "", false)
	if err != nil {
		t.Errorf("unexpected error when creating alternative: %v", err)
	}
	altTwo, err := runes.NewAlternative("f2", "=", "2", false)
	if err != nil {
		t.Errorf("unexpected error when creating alternative: %v", err)
	}
	altThree, err := runes.NewAlternative("f3", ">", "2", false)
	if err != nil {
		t.Errorf("unexpected error when creating alternative: %v", err)
	}

	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = 0x01
	}
	newRune, err := runes.NewMasterRune(secret, "", "")
	if err != nil {
		t.Errorf("unexpected error when creating rune: %v", err)
	}
	err = newRune.AddRestriction(runes.Restriction{altOne, altTwo})
	if err != nil {
		t.Errorf("unexpected error when adding restriction to rune: %v", err)
	}
	err = newRune.AddRestriction(runes.Restriction{altThree})
	if err != nil {
		t.Errorf("unexpected error when adding restriction to rune: %v", err)
	}

	runestr := newRune.Encode()

	runeTwo, err := runes.RuneFromEncodedString(runestr)
	if err != nil {
		t.Errorf("unexpected error when creating rune from encoded rune string: %v", err)
	}

	if newRune.String() != runeTwo.String() {
		t.Errorf("unexpected rune inequality: %s and %s", newRune.String(), runeTwo.String())
	}
}

// TestCheck tests the Check method of the Rune struct
func TestCheck(t *testing.T) {
	masterRune, err := runes.NewMasterRune(make([]byte, 16), "", "")
	if err != nil {
		t.Errorf("unexpected error when creating rune: %v", err)
	}
	restr, err := runes.RestrictionFromString("foo=bar", false)
	if err != nil {
		t.Errorf("unexpected error when creating restriction: %v", err)
	}
	newRune, err := runes.NewRuneFromAuthbase(masterRune.Authcode(), "", "", []runes.Restriction{restr})
	if err != nil {
		t.Errorf("unexpected error when creating rune from authcode: %v", err)
	}
	runestr := newRune.Encode()

	if err = masterRune.Check(runestr, map[string]runes.Test{"foo": {"bar", runes.StandardTestFunc}}); err != nil {
		t.Errorf("unexpected error when testing master rune: %v", err)
	}
	if err = masterRune.Check(runestr, map[string]runes.Test{"foo": {"baz", runes.StandardTestFunc}}); !errors.Is(err, runes.ErrForbiddenValue) {
		t.Errorf("unexpected error when testing master rune: %v", err)
	}

	// this makes sense as a given rune was not issued by itself
	if err = newRune.Check(runestr, map[string]runes.Test{"foo": {"bar", runes.StandardTestFunc}}); !errors.Is(err, runes.ErrUnauthorizedRune) {
		t.Errorf("unexpected error when testing master rune: %v", err)
	}
	if err = newRune.Check(runestr, map[string]runes.Test{"foo": {"baz", runes.StandardTestFunc}}); !errors.Is(err, runes.ErrUnauthorizedRune) {
		t.Errorf("unexpected error when testing master rune: %v", err)
	}
}

// TestFieldWithPunctuation tests that we can create runes with punctuation in the values
func TestFieldWithPunctuation(t *testing.T) {
	restr, err := runes.RestrictionFromString("foo=bar.baz", false)
	if err != nil {
		t.Errorf("unexpected error when creating restriction: %v", err)
	}
	mr, err := runes.NewMasterRune(make([]byte, 32), "", "")
	if err != nil {
		t.Errorf("unexpected error when creating rune: %v", err)
	}
	err = mr.AddRestriction(restr)
	if err != nil {
		t.Errorf("unexpected error when adding restriction to rune: %v", err)
	}

	newRune, err := runes.RuneFromEncodedString(mr.Encode())
	if err != nil {
		t.Errorf("unexpected error parsing encoded rune: %v", err)
	}
	if newRune.String() != mr.String() {
		t.Errorf("unexpected result when comparing runes: %s and %s", newRune.String(), mr.String())
	}

	alt, err := runes.NewAlternative("foo", "=", runes.Punctuation, false)
	if err != nil {
		t.Errorf("unexpected error when creating alternative: %v", err)
	}
	restrTwo := runes.Restriction{alt}
	if restrTwo.String() != "foo="+strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(runes.Punctuation, "\\", "\\\\"), "|", "\\|"), "&", "\\&") {
		t.Errorf("unexpected result comparing encoded restriction: %s", restrTwo.String())
	}

	err = mr.AddRestriction(restrTwo)
	if err != nil {
		t.Errorf("unexpected error when adding restriction to rune: %v", err)
	}
	decodedBytes, err := base64.URLEncoding.DecodeString(mr.Encode())
	if err != nil {
		t.Errorf("unexpected error when base64 decoding rune: %v", err)
	}
	if string(decodedBytes[32:]) != "foo=bar.baz&foo="+strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(runes.Punctuation, "\\", "\\\\"), "|", "\\|"), "&", "\\&") {
		t.Errorf("unexpected result when comparing decoded runes: %s", string(decodedBytes[32:]))
	}

	restrThree, err := runes.RestrictionFromString("foo=1", false)
	if err != nil {
		t.Errorf("unexpected error when creating restriction: %v", err)
	}
	err = mr.AddRestriction(restrThree)
	if err != nil {
		t.Errorf("unexpected error when adding restriction to rune: %v", err)
	}
	decodedBytes, err = base64.URLEncoding.DecodeString(mr.Encode())
	if err != nil {
		t.Errorf("unexpected error when base64 decoding rune: %v", err)
	}
	if string(decodedBytes[32:]) != "foo=bar.baz&foo="+strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(runes.Punctuation, "\\", "\\\\"), "|", "\\|"), "&", "\\&")+"&foo=1" {
		t.Errorf("unexpected result when comparing decoded runes: %s", string(decodedBytes[32:]))
	}

	mewRune, err := runes.RuneFromEncodedString(mr.Encode())
	if err != nil {
		t.Errorf("unexpected error when parsing encoded rune: %v", err)
	}
	if mewRune.String() != mr.String() {
		t.Errorf("unexpected result when comparing runes: %s and %s", mewRune.String(), mr.String())
	}
}

// TestCustomTestFunc tests whether a custom test function behaves as expected
func TestCustomTestFunc(t *testing.T) {
	var (
		callmePass runes.TestFunc = func(alt *runes.Alternative, v interface{}) error {
			return nil
		}
		callmeFail runes.TestFunc = func(alt *runes.Alternative, v interface{}) error {
			return errors.New("failed")
		}
	)

	restr, err := runes.RestrictionFromString("callme=bar.baz", false)
	if err != nil {
		t.Errorf("unexpected error when parsing restriction: %v", err)
	}
	if err = restr.Test(map[string]runes.Test{"callme": {nil, callmePass}}); err != nil {
		t.Errorf("unexpected error when testing restriction: %v", err)
	}
	if err = restr.Test(map[string]runes.Test{"callme": {nil, callmeFail}}); err == nil {
		t.Error("expected error when testing restriction and got none")
	}
}

// TestIdRestriction tests the ID restriction can be created and behaves as expected
func TestIdRestriction(t *testing.T) {
	mr, err := runes.NewMasterRune(make([]byte, 16), "1", "")
	if err != nil {
		t.Errorf("unexpected error when creating rune with id: %v", err)
	}
	if len(mr.Restrictions) != 1 {
		t.Errorf("unexpected result when checking length of restrictions: %v", len(mr.Restrictions))
	}
	if mr.Restrictions[0].String() != "=1" {
		t.Errorf("unexpected result when checking encoded restriction: %s", mr.Restrictions[0].String())
	}

	if err = mr.AreRestrictionsMet(make(map[string]runes.Test)); err != nil {
		t.Errorf("unexpected error when checking if rune restrictions are met: %v", err)
	}

	if err = mr.AreRestrictionsMet(map[string]runes.Test{"": {"1", runes.StandardTestFunc}}); err != nil {
		t.Errorf("unexpected error when checking if rune restrictions are met: %v", err)
	}
	if err = mr.AreRestrictionsMet(map[string]runes.Test{"": {"2", runes.StandardTestFunc}}); !errors.Is(err, runes.ErrForbiddenValue) {
		t.Errorf("unexpected error when checking if rune restrictions are met: %v", err)
	}

	mr2, err := runes.NewMasterRune(make([]byte, 16), "1", "2")
	if err != nil {
		t.Errorf("unexpected error when creating rune with id: %v", err)
	}
	if len(mr2.Restrictions) != 1 {
		t.Errorf("unexpected result when checking length of restrictions: %v", len(mr.Restrictions))
	}
	if mr2.Restrictions[0].String() != "=1-2" {
		t.Errorf("unexpected result when checking encoded restriction: %s", mr.Restrictions[0].String())
	}

	if err = mr2.AreRestrictionsMet(make(map[string]runes.Test)); !errors.Is(err, runes.ErrIdUknownVersion) {
		t.Errorf("unexpected error when checking if rune restrictions are met: %v", err)
	}

	if err = mr2.AreRestrictionsMet(map[string]runes.Test{"": {"1", runes.StandardTestFunc}}); !errors.Is(err, runes.ErrForbiddenValue) {
		t.Errorf("unexpected error when checking if rune restrictions are met: %v", err)
	}
	if err = mr2.AreRestrictionsMet(map[string]runes.Test{"": {"1-2", runes.StandardTestFunc}}); err != nil {
		t.Errorf("unexpected error when checking if rune restrictions are met: %v", err)
	}
}

// TestUniqueIdRestrictions tests if unique_id restrictions behave as expected
func TestUniqueIdRestrictions(t *testing.T) {
	secret := make([]byte, 16)
	mr, err := runes.NewMasterRune(secret, "1", "")
	if err != nil {
		t.Errorf("unexpected error when creating new rune: %v", err)
	}
	alt, err := runes.NewAlternative("", "=", "2", true)
	if err != nil {
		t.Errorf("unexpected error when creating alternative: %v", err)
	}

	mr2, err := runes.RuneFromEncodedString(mr.Encode())
	if err != nil {
		t.Errorf("unexpected error when parsing rune: %v", err)
	}
	if err = mr2.AddRestriction(runes.Restriction{alt}); err != nil {
		t.Errorf("unexpected error when adding restriction to rune: %v", err)
	}
	if _, err = runes.RuneFromEncodedString(mr2.Encode()); !errors.Is(err, runes.ErrIdFieldForbidden) {
		t.Errorf("unexpected error when parsing rune: %v", err)
	}

	mr3, err := runes.RuneFromEncodedString(mr.Encode())
	if err != nil {
		t.Errorf("unexpected error when parsing rune: %v", err)
	}
	for _, cond := range []string{"!", "/", "^", "$", "~", "<", ">", "{", "}", "#"} {
		mr3.Restrictions[0][0].Condition = cond
		if _, err = runes.RuneFromEncodedString(mr3.Encode()); !errors.Is(err, runes.ErrInvalidUniqueIdCond) {
			t.Errorf("unexpected error when parsing rune: %v", err)
		}
	}

	newRune, err := runes.NewMasterRune(make([]byte, 16), "", "")
	if err != nil {
		t.Errorf("unexpected error when creating rune: %v", err)
	}
	alt2, err := runes.NewAlternative("f", "=", "1", false)
	if err != nil {
		t.Errorf("unexpected error when creating alternative: %v", err)
	}
	if err = newRune.AddRestriction(runes.Restriction{alt, alt2}); err != nil {
		t.Errorf("unexpected error when adding restriction to rune: %v", err)
	}
	if _, err = runes.RuneFromEncodedString(newRune.Encode()); !errors.Is(err, runes.ErrIdFieldHasAlts) {
		t.Errorf("unexpected error when parsing rune: %v", err)
	}
}

// TODO - Create full testing suite (Don't forget creating runes with alts in restrictions)
