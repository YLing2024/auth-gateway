package oauth

import "testing"

func TestChallengeForKnownVector(t *testing.T) {
	// RFC 7636 Appendix B.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := ChallengeFor(verifier); got != want {
		t.Fatalf("ChallengeFor = %q, want %q", got, want)
	}
}

func TestNewPKCE(t *testing.T) {
	p, err := NewPKCE()
	if err != nil {
		t.Fatal(err)
	}
	if p.Verifier == "" || p.Challenge == "" {
		t.Fatal("empty verifier/challenge")
	}
	if ChallengeFor(p.Verifier) != p.Challenge {
		t.Fatal("challenge does not match verifier")
	}
	p2, _ := NewPKCE()
	if p.Verifier == p2.Verifier {
		t.Fatal("verifier repeated")
	}
}
