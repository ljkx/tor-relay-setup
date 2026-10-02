package serve

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestHashPassword(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Errorf("hash %q", h)
	}
	p, err := parseHash(h)
	if err != nil || len(p.salt) != 16 || len(p.key) != 32 {
		t.Fatalf("parse %+v %v", p, err)
	}
	if !VerifyPassword(h, "correct horse battery staple") {
		t.Error("the right password was rejected")
	}
	if VerifyPassword(h, "correct horse battery stapl") || VerifyPassword(h, "") {
		t.Error("a wrong password was accepted")
	}
	h2, _ := HashPassword("correct horse battery staple")
	if h2 == h {
		t.Error("two hashes of one password are equal: no salt")
	}
	for _, short := range []string{"", "short", "elevenchars"} {
		if _, err := HashPassword(short); err == nil {
			t.Errorf("%q accepted", short)
		}
	}
	if _, err := HashPassword(strings.Repeat("x", MaxPasswordLength+1)); err == nil {
		t.Error("overlong password accepted")
	}
}

func TestVerifyRejectsBadHashes(t *testing.T) {
	good := cheapHash("correct horse battery")
	if !VerifyPassword(good, "correct horse battery") {
		t.Fatal("cheap hash")
	}
	parts := strings.Split(good, "$")
	for _, bad := range []string{
		"", "plain", "$argon2i$v=19$m=8192,t=1,p=1$" + parts[4] + "$" + parts[5],
		"$argon2id$v=16$m=8192,t=1,p=1$" + parts[4] + "$" + parts[5],
		"$argon2id$v=19$m=1024,t=1,p=1$" + parts[4] + "$" + parts[5],
		"$argon2id$v=19$m=8192,t=99,p=1$" + parts[4] + "$" + parts[5],
		"$argon2id$v=19$m=8192,t=1,p=0$" + parts[4] + "$" + parts[5],
		"$argon2id$v=19$m=8192,t=1,p=1,x=2$" + parts[4] + "$" + parts[5],
		"$argon2id$v=19$m=8192,t=1,p=1$!!$" + parts[5],
		"$argon2id$v=19$m=8192,t=1,p=1$" + parts[4] + "$c2hvcnQ",
	} {
		if VerifyPassword(bad, "correct horse battery") {
			t.Errorf("%q verified", bad)
		}
	}
	if VerifyPassword(good, strings.Repeat("x", MaxPasswordLength+1)) {
		t.Error("overlong password")
	}
}

func TestTokens(t *testing.T) {
	tok, sum, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	tok2, _, _ := NewToken()
	if !strings.HasPrefix(tok, "trs_") || len(tok) != 47 || tok == tok2 || sum != TokenSum(tok) || len(sum) != 64 {
		t.Errorf("token %q sum %q", tok, sum)
	}
	raw, _ := hex.DecodeString(sum)
	if !tokenMatches(tok, raw) || tokenMatches(tok2, raw) || tokenMatches("", raw) || tokenMatches(tok, nil) {
		t.Error("tokenMatches")
	}
}
