package runes

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"
	"unicode"
)

var (
	Punctuation              = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
	validConditions          = "!=/^$~<>{}#"
	ErrInvalidField          = errors.New("field not valid")
	ErrInvalidCondition      = errors.New("condition not valid")
	ErrMissingField          = errors.New("missing field in test")
	ErrFieldIsPresent        = errors.New("field is present")
	ErrForbiddenValue        = errors.New("forbidden value")
	ErrInvalidValuePrefix    = errors.New("value has invalid perfix")
	ErrInvalidValueSuffix    = errors.New("value has invalid suffix")
	ErrValueDoesntContain    = errors.New("value does not contain substring")
	ErrValueTooLarge         = errors.New("value too large")
	ErrValueTooSmall         = errors.New("value too small")
	ErrWrongLexicOrder       = errors.New("wrong lexicographical order")
	ErrNoRestrictions        = errors.New("no restrictions")
	ErrNoOperator            = errors.New("restriction contains no operator")
	ErrIdFieldHasAlts        = errors.New("id field can't have alternatives")
	ErrExtraChars            = errors.New("restriction has extra ending characters")
	ErrInvalidRunePrefix     = errors.New("rune strings must start with 64 hex digits then '-'")
	ErrSecretTooLarge        = errors.New("secret too large")
	ErrCondValueTypeMismatch = errors.New("condition and test value type mismatch")
	ErrUnauthorizedRune      = errors.New("unauthorized rune")
	ErrInvalidUniqueIdCond   = errors.New("unique_id condition must be '='")
	ErrIdUknownVersion       = errors.New("id unknown version")
	ErrIdHasHyphens          = errors.New("hyphen not allowed in unique_id")
	ErrIdFieldForbidden      = errors.New("unique_id fiield not valid here")
	shaPrefix                = "sha\x03"
)

// padlen64 returnss the amount which will increase x until it's divisable by 64
func padlen64(x int) int {
	return (64 - (x % 64)) % 64
}

// EndShastream simulates a SHA-256 ending pad
func EndShastream(length int) []byte {
	b := []byte{0x80}
	b = append(b, make([]byte, padlen64(length+1+8))...)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(length*8))
	return append(b, buf...)
}

type Alternative struct {
	Field     string
	Value     string
	Condition string
}

// NewAlternative creates a new Alternative
func NewAlternative(field, cond, value string, allowIdField bool) (*Alternative, error) {
	if strings.ContainsAny(field, Punctuation) {
		return nil, ErrInvalidField
	}
	if !strings.ContainsAny(cond, validConditions) {
		return nil, ErrInvalidCondition
	}
	if field == "" {
		if cond != "=" {
			return nil, ErrInvalidUniqueIdCond
		} else if !allowIdField {
			return nil, ErrIdFieldForbidden
		}
	}
	return &Alternative{
		Field:     field,
		Value:     value,
		Condition: cond,
	}, nil
}

// TestFunc is a type for creating custom tests for restrictions
type TestFunc func(alt *Alternative, v interface{}) error

// Test is a struct made for passing a value and a test function for Restriction testing
type Test struct {
	Value    interface{}
	TestFunc TestFunc
}

// TODO - Finish covering all base type cases
var StandardTestFunc TestFunc = func(alt *Alternative, v interface{}) error {
	switch value := v.(type) {
	case string:
		switch alt.Condition {
		case "!":
			return fmt.Errorf("%s: %w", alt.Field, ErrFieldIsPresent)
		case "=":
			if alt.Value != value {
				return fmt.Errorf("%s: %w", alt.Value, ErrForbiddenValue)
			}
		case "/":
			if alt.Value == value {
				return fmt.Errorf("%s: %w", alt.Value, ErrForbiddenValue)
			}
		case "^":
			if !strings.HasPrefix(value, alt.Value) {
				return fmt.Errorf("%s: %w", alt.Value, ErrInvalidValuePrefix)
			}
		case "$":
			if !strings.HasSuffix(value, alt.Value) {
				return fmt.Errorf("%s: %w", alt.Value, ErrInvalidValueSuffix)
			}
		case "~":
			if !strings.Contains(value, alt.Value) {
				return fmt.Errorf("%s: %w", alt.Value, ErrValueDoesntContain)
			}
		case "{":
			if !(value < alt.Value) {
				return fmt.Errorf("%s: %w", alt.Value, ErrWrongLexicOrder)
			}
		case "}":
			if !(value > alt.Value) {
				return fmt.Errorf("%s: %w", alt.Value, ErrWrongLexicOrder)
			}
		default:
			return fmt.Errorf("%s & %T: %w", alt.Condition, value, ErrCondValueTypeMismatch)
		}
	case int:
		switch alt.Condition {
		case "=":
			valueAsInt, err := strconv.ParseInt(alt.Value, 10, 64)
			if err != nil {
				return fmt.Errorf("%s: %w", alt.Value, err)
			}
			if int64(value) != valueAsInt {
				return fmt.Errorf("%s: %w", alt.Value, ErrForbiddenValue)
			}
		case "/":
			valueAsInt, err := strconv.ParseInt(alt.Value, 10, 64)
			if err != nil {
				return fmt.Errorf("%s: %w", alt.Value, err)
			}
			if int64(value) == valueAsInt {
				return fmt.Errorf("%s: %w", alt.Value, ErrForbiddenValue)
			}
		case "<":
			valueAsInt, err := strconv.ParseInt(alt.Value, 10, 64)
			if err != nil {
				return fmt.Errorf("%s: %w", alt.Value, err)
			}
			if !(int64(value) < valueAsInt) {
				return fmt.Errorf("%s: %w", alt.Value, ErrValueTooLarge)
			}
		case ">":
			valueAsInt, err := strconv.ParseInt(alt.Value, 10, 64)
			if err != nil {
				return fmt.Errorf("%s: %w", alt.Value, err)
			}
			if !(int64(value) > valueAsInt) {
				return fmt.Errorf("%s: %w", alt.Value, ErrValueTooSmall)
			}
		default:
			return fmt.Errorf("%s & %T: %w", alt.Condition, value, ErrCondValueTypeMismatch)
		}
	}
	return nil
}

// Test Checks if the alternative passes the given tests
func (a *Alternative) Test(tests map[string]Test) error {
	// This always passes
	if a.Condition == "#" {
		return nil
	}
	// check if field exists in tests
	if _, ok := tests[a.Field]; !ok {
		// unique_id fields
		if a.Field == "" {
			if strings.Contains(a.Value, "-") {
				return ErrIdUknownVersion
			}
			return nil
		}
		if a.Condition == "!" {
			return nil
		}
		return fmt.Errorf("%s: %w", a.Field, ErrMissingField)
	}
	return tests[a.Field].TestFunc(a, tests[a.Field].Value)
}

// String formats the alternative into a string
func (a *Alternative) String() string {
	return a.Field + a.Condition + strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(a.Value, "\\", "\\\\"), "|", "\\|"), "&", "\\&")
}

// decodeAlternative pulls alternatives from encoded string and returns the remainder
func decodeAlternative(encodedString string, allowIdField bool) (*Alternative, string, error) {
	var (
		endOff    int
		condition string
	)
	for endOff < len(encodedString) {
		if strings.ContainsAny(string(encodedString[endOff]), Punctuation) {
			condition = string(encodedString[endOff])
			break
		}
		endOff += 1
	}
	if condition == "" {
		return nil, "", fmt.Errorf("%s: %w", encodedString, ErrNoOperator)
	}
	field := string(encodedString[:endOff])
	endOff += 1

	var value string
loop:
	for endOff < len(encodedString) {
		switch encodedString[endOff] {
		case '|':
			endOff += 1
			break loop
		case '&':
			break loop
		case '\\':
			endOff += 1
		}
		value += string(encodedString[endOff])
		endOff += 1
	}
	alt, err := NewAlternative(field, condition, value, allowIdField)
	return alt, string(encodedString[endOff:]), err
}

type Restriction []*Alternative

// Test performs the given tests on the restrictions
func (r Restriction) Test(tests map[string]Test) error {
	var bigErr error
	for _, alt := range r {
		err := alt.Test(tests)
		// if any tests pass we return nil
		if err == nil {
			return err
		}
		bigErr = errors.Join(bigErr, err)
	}
	return bigErr
}

// decodeRestriction pulls restrictions from encoded strings
func decodeRestriction(encodedString string, allowIdField bool) (Restriction, string, error) {
	var alts Restriction
	for len(encodedString) != 0 {
		if strings.HasPrefix(encodedString, "&") {
			encodedString = string(encodedString[1:])
			break
		}
		alt, newEncodedString, err := decodeAlternative(encodedString, allowIdField)
		if err != nil {
			return nil, "", err
		}
		alts = append(alts, alt)
		encodedString = newEncodedString
		allowIdField = false // id fields aren't allowed after the first alternative
	}
	if len(alts) > 1 && alts[0].Field == "" {
		return nil, "", ErrIdFieldHasAlts
	}
	return alts, encodedString, nil
}

// RestrictionFromString creates restrictions from an escaped string
func RestrictionFromString(encodedString string, allowIdField bool) (Restriction, error) {
	encodedString = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, encodedString)
	restriction, remainder, err := decodeRestriction(encodedString, allowIdField)
	if err != nil {
		return nil, err
	}
	if len(remainder) != 0 {
		return nil, fmt.Errorf("%s: %w", remainder, ErrExtraChars)
	}
	return restriction, nil
}

// String formats the restriction into a string
func (r Restriction) String() string {
	var altStrings []string
	for _, alt := range r {
		altStrings = append(altStrings, alt.String())
	}
	return strings.Join(altStrings, "|")
}

// UniqueIdRestriction creates a unique Id restriction
func UniqueIdRestriction(id, version string) (Restriction, error) {
	if strings.Contains(id, "-") {
		return nil, ErrIdHasHyphens
	}
	if version != "" {
		id += fmt.Sprintf("-%s", version)
	}
	alt, err := NewAlternative("", "=", id, true)
	if err != nil {
		return nil, err
	}
	return Restriction{alt}, nil
}

type Rune struct {
	Restrictions []Restriction
	uniqueId     string
	version      string
	hash         hash.Hash // This hash struct keeps the cumulative state with all added restrictions
	hashBase     hash.Hash // This hash struct only keeps the base state
}

// NewMasterRune creates a new master rune
func NewMasterRune(secret []byte, id, version string) (*Rune, error) {
	if len(secret)+1+8 > 64 {
		return nil, ErrSecretTooLarge
	}
	h := sha256.New()
	hBase := sha256.New()
	secret = append(secret, EndShastream(len(secret))...)
	_, err := h.Write(secret)
	if err != nil {
		return nil, err
	}
	_, err = hBase.Write(secret)
	if err != nil {
		return nil, err
	}
	r := &Rune{
		hash:     h,
		hashBase: hBase,
		uniqueId: id,
		version:  version,
	}
	if id != "" {
		restr, err := UniqueIdRestriction(id, version)
		if err != nil {
			return nil, err
		}
		err = r.AddRestriction(restr)
		if err != nil {
			return nil, err
		}
	}
	return r, nil
}

// NewRuneFromAuthbase creates a new rune from a given authbase and list of restrictions
func NewRuneFromAuthbase(authbase []byte, uniqueId, version string, restrictions []Restriction) (*Rune, error) {
	// append sha prefix and then unmarshal sha256 state into hash struct
	base := make([]byte, 0, 108)
	base = append(base, shaPrefix...)
	base = append(base, authbase...)
	base = base[:100]
	base = binary.BigEndian.AppendUint64(base, uint64(len(authbase)+padlen64(len(authbase))))
	h := sha256.New()
	hBase := sha256.New()
	unmarshaler := h.(encoding.BinaryUnmarshaler)
	baseUnmarshaler := h.(encoding.BinaryUnmarshaler)
	err := unmarshaler.UnmarshalBinary(base)
	if err != nil {
		return nil, err
	}
	err = baseUnmarshaler.UnmarshalBinary(base)
	if err != nil {
		return nil, err
	}
	r := &Rune{
		hash:     h,
		hashBase: hBase,
		uniqueId: uniqueId,
		version:  version,
	}
	// unique_id restrictions first
	if uniqueId != "" {
		restr, err := UniqueIdRestriction(uniqueId, version)
		if err != nil {
			return nil, err
		}
		err = r.AddRestriction(restr)
		if err != nil {
			return nil, err
		}
	}
	for _, restr := range restrictions {
		if err = r.AddRestriction(restr); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// AddRestrictions adds new restrictions to the rune
func (r *Rune) AddRestriction(restriction Restriction) error {
	r.Restrictions = append(r.Restrictions, restriction)
	_, err := r.hash.Write([]byte(restriction.String()))
	if err != nil {
		return err
	}
	_, err = r.hash.Write(EndShastream(len(restriction.String())))
	return err
}

// AreRestrictionsMet tests the rune restrictions. If any fail, returns an error
func (r *Rune) AreRestrictionsMet(tests map[string]Test) error {
	for _, restriction := range r.Restrictions {
		if err := restriction.Test(tests); err != nil {
			return err
		}
	}
	return nil
}

// Authcode returns the SHA256 of the authbase
func (r *Rune) Authcode() []byte {
	marshaler := r.hash.(encoding.BinaryMarshaler)
	authcode, _ := marshaler.MarshalBinary()
	return authcode[4:36]
}

// String returns the string encoded version of the rune
func (r *Rune) String() string {
	var resStrs []string
	for _, restriction := range r.Restrictions {
		resStrs = append(resStrs, restriction.String())
	}
	return hex.EncodeToString(r.Authcode()) + ":" + strings.Join(resStrs, "&")
}

// Encode returns the base64 encoded rune
func (r *Rune) Encode() string {
	var resStrs []string
	for _, restriction := range r.Restrictions {
		resStrs = append(resStrs, restriction.String())
	}
	return base64.URLEncoding.EncodeToString(append(r.Authcode(), []byte(strings.Join(resStrs, "&"))...))
}

// IsRuneAuthorized checks whether or not a given rune has been authorized by the master rune
func (r *Rune) IsRuneAuthorized(otherRune *Rune) bool {
	// create a copy of the hash struct
	marshaler := r.hashBase.(encoding.BinaryMarshaler)
	state, _ := marshaler.MarshalBinary()
	hCopy := sha256.New()
	unmarshaler := hCopy.(encoding.BinaryUnmarshaler)
	unmarshaler.UnmarshalBinary(state)
	// update hash state with encoded restrictions
	for _, restriction := range otherRune.Restrictions {
		encodedRes := []byte(restriction.String())
		hCopy.Write(encodedRes)
		hCopy.Write(EndShastream(len(encodedRes)))
	}
	newMarshal := hCopy.(encoding.BinaryMarshaler)
	authbase, _ := newMarshal.MarshalBinary()
	return bytes.Equal(otherRune.Authcode(), authbase[4:4+hCopy.Size()])
}

// Check checks if a given rune is authorized by the parent rune and passes the given tests
func (r *Rune) Check(encodedRune string, tests map[string]Test) error {
	newRune, err := RuneFromEncodedString(encodedRune)
	if err != nil {
		return err
	}
	if !r.IsRuneAuthorized(newRune) {
		return ErrUnauthorizedRune
	}
	return newRune.AreRestrictionsMet(tests)
}

// RuneFromAuthcode parses a rune from a given authcode and a list of restrictions
func RuneFromAuthcode(authcode []byte, restrictions []Restriction) (*Rune, error) {
	// append sha prefix and then unmarshal sha256 state into hash struct
	authbase := make([]byte, 0, 108)
	authbase = append(authbase, shaPrefix...)
	authbase = append(authbase, authcode...)
	authbase = authbase[:100]
	runeLength := len(authcode) + padlen64(len(authcode)) // may have to remove padlen64 of len(authcode)
	for _, restr := range restrictions {
		runeLength += len(restr.String())
		runeLength += padlen64(runeLength)
	}
	authbase = binary.BigEndian.AppendUint64(authbase, uint64(runeLength))
	h := sha256.New()
	hBase := sha256.New()
	unmarshaler := h.(encoding.BinaryUnmarshaler)
	baseUnmarshaler := h.(encoding.BinaryUnmarshaler)
	err := unmarshaler.UnmarshalBinary(authbase)
	if err != nil {
		return nil, err
	}
	err = baseUnmarshaler.UnmarshalBinary(authbase)
	if err != nil {
		return nil, err
	}
	return &Rune{
		hash:         h,
		hashBase:     hBase,
		Restrictions: restrictions,
	}, nil
}

// RuneFromString parses a rune from a rune string
func RuneFromString(runeString string) (*Rune, error) {
	if len(runeString) < 64 || runeString[64] != ':' {
		return nil, ErrInvalidRunePrefix
	}
	authbase, err := hex.DecodeString(string(runeString[:64]))
	if err != nil {
		return nil, err
	}
	restrStr := string(runeString[65:])
	var restrictions []Restriction
	allowIdField := true // allow id field at the front
	for len(restrStr) != 0 {
		restr, newRestrStr, err := decodeRestriction(restrStr, allowIdField)
		if err != nil {
			return nil, err
		}
		restrictions = append(restrictions, restr)
		restrStr = newRestrStr
		allowIdField = false
	}
	newRune, err := RuneFromAuthcode(authbase, restrictions)
	if err != nil {
		return nil, err
	}
	return newRune, nil
}

// RuneFromEncodedString parses a rune from an encoded rune string
func RuneFromEncodedString(encodedString string) (*Rune, error) {
	runeBytes, err := base64.URLEncoding.DecodeString(encodedString)
	if err != nil {
		return nil, err
	}
	return RuneFromString(hex.EncodeToString(runeBytes[:32]) + ":" + string(runeBytes[32:]))
}
