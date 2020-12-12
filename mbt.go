package mbt

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"github.com/vmihailenco/msgpack/v5"
)

const (
	DELIMITER byte = 0x2e
)

type Mbt []byte

type Header struct {
	Alg string
	Typ string
}

type Payload struct {
	Sub string
	Iat int64
}

type smbt struct {
	header    Header
	payload   Payload
	signature []byte
}

func (mbt *Mbt) String() string {
	smbt := mbt.toSmbt()
	res := fmt.Sprintf("Header: %v, Payload: %v, Signature: %v", smbt.header, smbt.payload, smbt.signature)
	return res
}

func (mbt *Mbt) toSmbt() *smbt {
	raw := []byte(*mbt)
	dotPos := findAll(raw, DELIMITER)
	hb := raw[:dotPos[0]]
	pb := raw[dotPos[0]+1 : dotPos[1]]
	sb := raw[dotPos[1]+1:]

	smbt := smbt{
		signature: make([]byte, len(sb)),
	}
	err := msgpack.Unmarshal(hb, &smbt.header)
	if err != nil {
		panic(err)
	}
	err = msgpack.Unmarshal(pb, &smbt.payload)
	if err != nil {
		panic(err)
	}
	copy(smbt.signature, sb)
	return &smbt
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

func New(h *Header, p *Payload, key *[]byte) (*Mbt, error) {
	hb, err := msgpack.Marshal(h)
	if err != nil {
		return nil, err
	}
	pb, err := msgpack.Marshal(p)
	if err != nil {
		return nil, err
	}

	var mbt Mbt
	mbt = append(mbt, hb...)
	mbt = append(mbt, DELIMITER)
	mbt = append(mbt, pb...)

	signature := getSignature(mbt, *key)

	mbt = append(mbt, DELIMITER)
	mbt = append(mbt, signature...)
	return &mbt, nil
}

func getSignature(msg, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return mac.Sum(nil)
}
