package mbt_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/goro9/go-mbt"
	"github.com/vmihailenco/msgpack/v5"
)

const (
	KEY       = "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"
	KEY_WRONG = "\x21\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"
)

func TestTemp(t *testing.T) {
	h := mbt.HeaderField{
		Alg: "HS256",
		Typ: "mbt",
	}
	p := mbt.PayloadClaimStd{
		Sub: "test",
		Iat: time.Now().Unix(),
	}
	key := []byte(KEY)
	token, err := mbt.New(&h, &p, &key)
	if err != nil {
		t.Fatalf("failed test: %v", err)
	}
	fmt.Println(len(*token), token)

	if !token.Verify(&key) {
		t.Fatalf("failed test")
	}

	keyWrong := []byte(KEY_WRONG)
	if token.Verify(&keyWrong) {
		t.Fatalf("failed test")
	}
}

func TestMsgpack(t *testing.T) {
	hstr := mbt.HeaderField{
		Alg: "HS256",
		Typ: "mbt",
	}
	hbin, err := msgpack.Marshal(&hstr)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(hbin))

	header := make(map[string]interface{})
	header["alg"] = "HS256"
	header["typ"] = "mbt"
	hbin, err = msgpack.Marshal(&header)
	if err != nil {
		panic(err)
	}

	var item map[string]interface{}
	err = msgpack.Unmarshal(hbin, &item)
	if err != nil {
		panic(err)
	}
	fmt.Println(item)

	payload := make(map[string]interface{})
	payload["sub"] = "test"
	payload["iat"] = time.Now().Unix()
	pbin, err := msgpack.Marshal(&payload)
	if err != nil {
		panic(err)
	}

	var pres map[string]interface{}
	err = msgpack.Unmarshal(pbin, &pres)
	if err != nil {
		panic(err)
	}
	fmt.Println(pres)
}
