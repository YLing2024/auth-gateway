// Command echoupstream is an offline test upstream. It echoes request headers
// as JSON, streams a large body for download tests, and echoes WebSocket
// frames. It must never be deployed.
package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func main() {
	addr := flag.String("addr", "127.0.0.1:18932", "listen address")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/big", handleBig)
	mux.HandleFunc("/", handleEcho)
	log.Printf("echoupstream listening on %s", *addr)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatalf("echoupstream: %v", err)
	}
}

func handleEcho(w http.ResponseWriter, r *http.Request) {
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		serveWebSocket(w, r)
		return
	}
	headers := map[string][]string(r.Header.Clone())
	// Report the real presentation of a few fields for easy assertions.
	out := map[string]any{
		"method":        r.Method,
		"path":          r.URL.RequestURI(),
		"host":          r.Host,
		"headers":       headers,
		"x_auth_user":   r.Header.Get("X-Auth-User"),
		"x_auth_app":    r.Header.Get("X-Auth-App"),
		"x_auth_sid":    r.Header.Get("X-Auth-Sid"),
		"authorization": r.Header.Get("Authorization"),
		"cookie":        r.Header.Get("Cookie"),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func handleBig(w http.ResponseWriter, r *http.Request) {
	mb := 50
	if v := r.URL.Query().Get("mb"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			mb = n
		}
	}
	total := int64(mb) * 1024 * 1024
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(total, 10))
	buf := make([]byte, 64*1024)
	for i := range buf {
		buf[i] = 'A'
	}
	var written int64
	for written < total {
		n := int64(len(buf))
		if rem := total - written; rem < n {
			n = rem
		}
		if _, err := w.Write(buf[:n]); err != nil {
			return
		}
		written += n
	}
}

// ── minimal WebSocket echo ───────────────────────────────────────────────

func serveWebSocket(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijack", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	sum := sha1.Sum([]byte(key + wsGUID))
	accept := base64.StdEncoding.EncodeToString(sum[:])
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := rw.WriteString(resp); err != nil {
		return
	}
	if err := rw.Flush(); err != nil {
		return
	}
	echoLoop(rw.Reader, conn)
}

func echoLoop(br *bufio.Reader, conn net.Conn) {
	for {
		opcode, payload, err := readFrame(br)
		if err != nil {
			return
		}
		switch opcode {
		case 0x8: // close
			_ = writeFrame(conn, 0x8, nil)
			return
		case 0x9: // ping
			_ = writeFrame(conn, 0xA, payload)
		case 0xA: // pong: ignore
		default: // text/binary: echo
			if err := writeFrame(conn, opcode, payload); err != nil {
				return
			}
		}
	}
}

func readFrame(br *bufio.Reader) (byte, []byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return 0, nil, err
	}
	opcode := hdr[0] & 0x0f
	masked := hdr[1]&0x80 != 0
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
		length = 0
		for _, b := range ext {
			length = length<<8 | int64(b)
		}
	}
	if length > 1<<24 {
		return 0, nil, fmt.Errorf("frame too large")
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(br, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(br, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return opcode, payload, nil
}

func writeFrame(conn net.Conn, opcode byte, payload []byte) error {
	out := []byte{0x80 | opcode}
	n := len(payload)
	switch {
	case n < 126:
		out = append(out, byte(n))
	case n < 1<<16:
		out = append(out, 126, byte(n>>8), byte(n))
	default:
		out = append(out, 127, 0, 0, 0, 0, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	out = append(out, payload...)
	_, err := conn.Write(out)
	return err
}
