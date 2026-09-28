// Command wsprobe is a tiny raw WebSocket client used by test/selftest.sh to
// verify the gateway's WebSocket passthrough without pulling in a websocket
// library. It is a test helper, not a deliverable service.
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func main() {
	addr := flag.String("addr", "127.0.0.1:18930", "gateway address")
	host := flag.String("host", "a.example.com", "Host header")
	path := flag.String("path", "/ws", "request path")
	cookie := flag.String("cookie", "", "Cookie header value")
	msg := flag.String("msg", "hello-ws", "text frame to send")
	flag.Parse()

	if err := run(*addr, *host, *path, *cookie, *msg); err != nil {
		fmt.Fprintln(os.Stderr, "wsprobe:", err)
		os.Exit(1)
	}
}

func run(addr, host, path, cookie, msg string) error {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	keyRaw := make([]byte, 16)
	if _, err := rand.Read(keyRaw); err != nil {
		return err
	}
	key := base64.StdEncoding.EncodeToString(keyRaw)

	var req strings.Builder
	fmt.Fprintf(&req, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&req, "Host: %s\r\n", host)
	req.WriteString("Upgrade: websocket\r\n")
	req.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&req, "Sec-WebSocket-Key: %s\r\n", key)
	req.WriteString("Sec-WebSocket-Version: 13\r\n")
	if cookie != "" {
		fmt.Fprintf(&req, "Cookie: %s\r\n", cookie)
	}
	req.WriteString("\r\n")
	if _, err := io.WriteString(conn, req.String()); err != nil {
		return err
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.Contains(statusLine, " 101 ") {
		return fmt.Errorf("handshake not 101: %q", strings.TrimSpace(statusLine))
	}
	sum := sha1.Sum([]byte(key + wsGUID))
	wantAccept := base64.StdEncoding.EncodeToString(sum[:])
	acceptOK := false
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return err
		}
		if line == "\r\n" {
			break
		}
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "Sec-WebSocket-Accept") {
			acceptOK = strings.TrimSpace(v) == wantAccept
		}
	}
	if !acceptOK {
		return fmt.Errorf("Sec-WebSocket-Accept mismatch")
	}
	fmt.Printf("HANDSHAKE 101 accept-ok host=%s path=%s\n", host, path)

	if err := writeClientFrame(conn, 0x1, []byte(msg)); err != nil {
		return err
	}
	opcode, payload, err := readServerFrame(br)
	if err != nil {
		return err
	}
	if opcode != 0x1 {
		return fmt.Errorf("unexpected opcode %#x", opcode)
	}
	if string(payload) != msg {
		return fmt.Errorf("echo mismatch: sent %q got %q", msg, string(payload))
	}
	fmt.Printf("ECHO %s\n", string(payload))
	return nil
}

func writeClientFrame(conn net.Conn, opcode byte, payload []byte) error {
	mask := make([]byte, 4)
	if _, err := rand.Read(mask); err != nil {
		return err
	}
	out := []byte{0x80 | opcode}
	n := len(payload)
	switch {
	case n < 126:
		out = append(out, 0x80|byte(n))
	case n < 1<<16:
		out = append(out, 0x80|126, byte(n>>8), byte(n))
	default:
		out = append(out, 0x80|127, 0, 0, 0, 0, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	out = append(out, mask...)
	for i, b := range payload {
		out = append(out, b^mask[i%4])
	}
	_, err := conn.Write(out)
	return err
}

func readServerFrame(br *bufio.Reader) (byte, []byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return 0, nil, err
	}
	opcode := hdr[0] & 0x0f
	length := int64(hdr[1] & 0x7f)
	switch length {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(br, ext); err != nil {
			return 0, nil, err
		}
		length = int64(ext[0])<<8 | int64(ext[1])
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(br, ext); err != nil {
			return 0, nil, err
		}
		for _, b := range ext {
			length = length<<8 | int64(b)
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(br, payload); err != nil {
		return 0, nil, err
	}
	return opcode, payload, nil
}
