package mbt_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/goro9/go-mbt"
)

const (
	KEY       = "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"
	KEY_WRONG = "\x21\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"
)

func TestTemp(t *testing.T) {
	h := mbt.Header{
		Alg: "HS256",
		Typ: "mbt",
	}
	p := mbt.Payload{
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
