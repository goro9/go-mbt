package mbt_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/goro9/go-mbt"
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
	key := []byte{0x11, 0x22, 0x33, 0x44}
	token, err := mbt.New(&h, &p, &key)
	if err != nil {
		t.Fatalf("failed test: %v", err)
	}

	fmt.Println(len(*token), token)
}
