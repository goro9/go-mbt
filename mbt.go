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

// Mbt is full token
type Mbt []byte

// MbtParts
type MbtParts struct {
	Hd []byte
	Py []byte
	Sg []byte
}

type Header struct {
	Alg string
	Typ string
}

type Payload struct {
	Sub string
	Iat int64
}

func (mbt *Mbt) String() string {
	mbtParts := mbt.ToMbtParts()
	var header Header
	err := msgpack.Unmarshal(mbtParts.Hd, &header)
	if err != nil {
		panic(err)
	}
	var payload Payload
	err = msgpack.Unmarshal(mbtParts.Py, &payload)
	if err != nil {
		panic(err)
	}
	res := fmt.Sprintf("Header: %v, Payload: %v, Signature: %v", header, payload, mbtParts.Sg)
	return res
}

func New(h *Header, p *Payload, key *[]byte) (*Mbt, error) {
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

	// mbt = append(mbt, DELIMITER, signature...)
	buf = append(buf, DELIMITER)
	buf = append(buf, signature...)
	return (*Mbt)(&buf), nil
}

func (mbt *Mbt) ToMbtParts() *MbtParts {
	raw := []byte(*mbt)
	dots := findAll(raw, DELIMITER)
	mbtParts := MbtParts{
		Hd: make([]byte, dots[0]),
		Py: make([]byte, dots[1]-(dots[0]+1)),
		Sg: make([]byte, len(raw)-(dots[1]+1)),
	}

	copy(mbtParts.Hd, raw[:dots[0]])
	copy(mbtParts.Py, raw[dots[0]+1:dots[1]])
	copy(mbtParts.Sg, raw[dots[1]+1:])
	return &mbtParts
}

func (mbt *Mbt) Verify(key *[]byte) bool {
	mbtParts := mbt.ToMbtParts()
	mbtUnsigned := append(mbtParts.Hd, DELIMITER)
	mbtUnsigned = append(mbtUnsigned, mbtParts.Py...)
	signature := getSignature(mbtUnsigned, *key)
	if bytes.Compare(signature, mbtParts.Sg) != 0 {
		return false
	}
	return true
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
