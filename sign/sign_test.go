package sign

import "testing"

import (
	"encoding/hex"
	"time"
)

//Clock: func(){ t, _ := time.Parse("Aug 30 12:36:00 -0000 UTC 2015"); return t }
func TestSignString(t *testing.T) {

	sts := `AWS4-HMAC-SHA256
20150830T123600Z
20150830/us-east-1/iam/aws4_request
f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59`
	key, _ := hex.DecodeString("c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9")
	want := "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"

	s := &Signer{}
	have := string(s.Sign(key, sts))

	if have != want {
		t.Logf("want=%s\thave=%s\n", want, have)
		t.Fail()
	}
}

func TestGenSignKey(t *testing.T) {
	tm, _ := time.Parse("20060102", "20150830")
	want := "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
	have := hex.EncodeToString(Gen(
		tm,
		"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		"us-east-1",
		"iam",
	))
	if have != want {
		t.Logf("want=%s\thave=%s\n", want, have)
		t.Fail()
	}
	// HMAC(HMAC(HMAC(HMAC("AWS4" + kSecret,"20150830"),"us-east-1"),"iam"),"aws4_request")
}
