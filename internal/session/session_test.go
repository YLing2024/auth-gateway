package session

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCryptRoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	c, err := NewCrypt(key)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := c.Encrypt("access-token-value")
	if err != nil {
		t.Fatal(err)
	}
	if ct == "access-token-value" || strings.Contains(ct, "access-token-value") {
		t.Fatal("ciphertext leaks plaintext")
	}
	pt, err := c.Decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}
	if pt != "access-token-value" {
		t.Fatalf("round trip = %q", pt)
	}
	// Two encryptions of the same value must differ (random nonce).
	ct2, _ := c.Encrypt("access-token-value")
	if ct == ct2 {
		t.Fatal("nonce reuse: ciphertext repeated")
	}
}

func TestCryptRejectsTampering(t *testing.T) {
	c, _ := NewCrypt([]byte("0123456789abcdef0123456789abcdef"))
	ct, _ := c.Encrypt("secret")
	bad := []byte(ct)
	if bad[0] == 'A' {
		bad[0] = 'B'
	} else {
		bad[0] = 'A'
	}
	if _, err := c.Decrypt(string(bad)); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}

func TestNilCryptNeverStoresPlaintext(t *testing.T) {
	var c *Crypt
	if _, err := c.Encrypt("secret"); err == nil {
		t.Fatal("nil crypt must refuse to encrypt")
	}
	if _, err := c.Decrypt("cipher"); err == nil {
		t.Fatal("nil crypt must refuse to decrypt")
	}
}

func TestCookieNameAndStrip(t *testing.T) {
	name := CookieName("android", "_session")
	if name != "__Host-android_session" {
		t.Fatalf("cookie name = %q", name)
	}
	got := StripGatewayCookies("theme=dark; __Host-android_session=abc; lang=zh", "_session")
	if got != "theme=dark; lang=zh" {
		t.Fatalf("StripGatewayCookies = %q", got)
	}
}

func TestRespClientRoundTrip(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFakeRedis(c)
		}
	}()

	r := NewRedis(ln.Addr().String(), "", 2, 2)
	if err := r.Ping(); err != nil {
		t.Fatalf("Ping over RESP: %v", err)
	}
	if _, ok, err := r.Get("gw:missing"); err != nil || ok {
		t.Fatalf("Get missing = (%v,%v), want (false,nil)", ok, err)
	}
	if err := r.SetEX("gw:sess:x", "{}", time.Minute); err != nil {
		t.Fatalf("SetEX: %v", err)
	}
	got, ok, err := r.Get("gw:sess:x")
	if err != nil || !ok || got != "stored" {
		t.Fatalf("Get = (%q,%v,%v)", got, ok, err)
	}
}

// serveFakeRedis is a deliberately tiny RESP server used only by tests.
func serveFakeRedis(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		args, err := readCommand(br)
		if err != nil {
			return
		}
		switch strings.ToUpper(args[0]) {
		case "AUTH", "SELECT", "SET", "EXPIRE", "DEL", "SAVE":
			c.Write([]byte("+OK\r\n"))
		case "PING":
			c.Write([]byte("+PONG\r\n"))
		case "GET", "GETDEL":
			if args[1] == "gw:sess:x" {
				c.Write([]byte("$6\r\nstored\r\n"))
			} else {
				c.Write([]byte("$-1\r\n"))
			}
		default:
			c.Write([]byte("-ERR unknown command\r\n"))
		}
	}
}

func readCommand(br *bufio.Reader) ([]string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if len(line) == 0 || line[0] != '*' {
		return nil, fmt.Errorf("bad array header %q", line)
	}
	n, err := strconv.Atoi(strings.TrimSpace(line[1:]))
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		hdr, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if len(hdr) == 0 || hdr[0] != '$' {
			return nil, fmt.Errorf("bad bulk header %q", hdr)
		}
		l, err := strconv.Atoi(strings.TrimSpace(hdr[1:]))
		if err != nil {
			return nil, err
		}
		buf := make([]byte, l+2)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:l]))
	}
	return args, nil
}
