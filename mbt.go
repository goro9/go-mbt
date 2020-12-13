package mbt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"github.com/vmihailenco/msgpack/v5"
)

const (
	// DELIMITER is delimiter for separate part
	DELIMITER byte = 0x2e
)

// Token ...
type Token []byte

// HeaderField ...
type HeaderField struct {
	Typ string `msgpack:"typ,omitempty"`
	Cty string `msgpack:"cty,omitempty"`
	Alg string `msgpack:"alg,omitempty"`
}

// PayloadClaimStd ...
type PayloadClaimStd struct {
	Iss string `msgpack:"iss,omitempty"`
	Sub string `msgpack:"sub,omitempty"`
	Aud string `msgpack:"aud,omitempty"`
	Exp int64  `msgpack:"exp,omitempty"`
	Nbf int64  `msgpack:"cbf,omitempty"`
	Iat int64  `msgpack:"iat,omitempty"`
	Jti string `msgpack:"jti,omitempty"`
}

// tokenParts ...
type tokenParts struct {
	header    []byte
	payload   []byte
	signature []byte
}

// New create Messagepack Binary Token
func New(h *HeaderField, p *PayloadClaimStd, key *[]byte) (*Token, error) {
	hb, err := msgpack.Marshal(h)
	if err != nil {
		return nil, err
	}
	pb, err := msgpack.Marshal(p)
	if err != nil {
		return nil, err
	}

	var buf []byte
	// buf = append(buf, hb..., DELIMITER, pb...)
	buf = append(buf, hb...)
	buf = append(buf, DELIMITER)
	buf = append(buf, pb...)

	signature := getSignature(buf, *key)

	// buf = append(buf, DELIMITER, signature...)
	buf = append(buf, DELIMITER)
	buf = append(buf, signature...)
	return (*Token)(&buf), nil
}

func (token *Token) String() string {
	mbtParts := token.toTokenParts()
	var header HeaderField
	err := msgpack.Unmarshal(mbtParts.header, &header)
	if err != nil {
		panic(err)
	}
	var payload PayloadClaimStd
	err = msgpack.Unmarshal(mbtParts.payload, &payload)
	if err != nil {
		panic(err)
	}
	res := fmt.Sprintf("Header: %v, Payload: %v, Signature: %v", header, payload, mbtParts.signature)
	return res
}

// Verify ...
func (token *Token) Verify(key *[]byte) bool {
	mbtParts := token.toTokenParts()
	mbtUnsigned := append(mbtParts.header, DELIMITER)
	mbtUnsigned = append(mbtUnsigned, mbtParts.payload...)
	signature := getSignature(mbtUnsigned, *key)
	if bytes.Compare(signature, mbtParts.signature) != 0 {
		return false
	}
	return true
}

func (token *Token) toTokenParts() *tokenParts {
	raw := []byte(*token)
	dots := findAll(raw, DELIMITER)
	mbtParts := tokenParts{
		header:    make([]byte, dots[0]),
		payload:   make([]byte, dots[1]-(dots[0]+1)),
		signature: make([]byte, len(raw)-(dots[1]+1)),
	}

	copy(mbtParts.header, raw[:dots[0]])
	copy(mbtParts.payload, raw[dots[0]+1:dots[1]])
	copy(mbtParts.signature, raw[dots[1]+1:])
	return &mbtParts
}

func findAll(list, target interface{}) []int {
	var res []int
	switch list.(type) {
	case []byte:
		buf := list.([]byte)
		for i := range buf {
			if buf[i] == target {
				res = append(res, i)
			}
		}
		return res
	default:
		return nil
	}
}

func getSignature(msg, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return mac.Sum(nil)
}
