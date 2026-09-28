// Package session owns all Redis state and the gateway session cookie.
package session

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// Redis is a minimal, dependency-free RESP client.
//
// Only the handful of commands the gateway needs are implemented. A small
// connection pool keeps concurrent requests from serialising on one socket.
type Redis struct {
	addr     string
	password string
	db       int

	pool chan *redisConn

	mu          sync.Mutex
	dialTimeout time.Duration
	ioTimeout   time.Duration
}

type redisConn struct {
	nc net.Conn
	br *bufio.Reader
	bw *bufio.Writer
}

// NewRedis dials nothing yet; connections are created lazily and validated on
// first use via Ping.
func NewRedis(addr, password string, db, poolSize int) *Redis {
	if poolSize <= 0 {
		poolSize = 8
	}
	return &Redis{
		addr:        addr,
		password:    password,
		db:          db,
		pool:        make(chan *redisConn, poolSize),
		dialTimeout: 5 * time.Second,
		ioTimeout:   10 * time.Second,
	}
}

// Ping verifies connectivity and authentication.
func (r *Redis) Ping() error {
	v, err := r.Do("PING")
	if err != nil {
		return err
	}
	s, _ := v.(string)
	if s != "PONG" {
		return fmt.Errorf("redis: unexpected PING reply %v", v)
	}
	return nil
}

// Do sends one command and returns the decoded reply. Replies map to: string
// (simple string, bulk string), int64 (integer), nil (nil bulk), []any
// (array). Server errors are returned as Go errors.
func (r *Redis) Do(args ...string) (any, error) {
	if len(args) == 0 {
		return nil, errors.New("redis: empty command")
	}
	c, err := r.get()
	if err != nil {
		return nil, err
	}
	if err := c.write(args); err != nil {
		c.close()
		return nil, err
	}
	v, err := c.read()
	if err != nil {
		c.close()
		return nil, err
	}
	r.put(c)
	return v, nil
}

func (r *Redis) get() (*redisConn, error) {
	select {
	case c := <-r.pool:
		return c, nil
	default:
	}
	return r.dial()
}

func (r *Redis) dial() (*redisConn, error) {
	nc, err := net.DialTimeout("tcp", r.addr, r.dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("redis: dial %s: %w", r.addr, err)
	}
	c := &redisConn{nc: nc, br: bufio.NewReader(nc), bw: bufio.NewWriter(nc)}
	if r.password != "" {
		if _, err := c.roundTrip("AUTH", r.password); err != nil {
			c.close()
			return nil, fmt.Errorf("redis: AUTH: %w", err)
		}
	}
	if r.db != 0 {
		if _, err := c.roundTrip("SELECT", strconv.Itoa(r.db)); err != nil {
			c.close()
			return nil, fmt.Errorf("redis: SELECT %d: %w", r.db, err)
		}
	}
	return c, nil
}

func (r *Redis) put(c *redisConn) {
	select {
	case r.pool <- c:
	default:
		c.close()
	}
}

func (c *redisConn) roundTrip(args ...string) (any, error) {
	if err := c.write(args); err != nil {
		return nil, err
	}
	return c.read()
}

func (c *redisConn) write(args []string) error {
	_ = c.nc.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.bw.WriteString("*" + strconv.Itoa(len(args)) + "\r\n"); err != nil {
		return err
	}
	for _, a := range args {
		if _, err := c.bw.WriteString("$" + strconv.Itoa(len(a)) + "\r\n"); err != nil {
			return err
		}
		if _, err := c.bw.WriteString(a); err != nil {
			return err
		}
		if _, err := c.bw.WriteString("\r\n"); err != nil {
			return err
		}
	}
	return c.bw.Flush()
}

func (c *redisConn) read() (any, error) {
	_ = c.nc.SetReadDeadline(time.Now().Add(10 * time.Second))
	return c.readReply()
}

func (c *redisConn) readReply() (any, error) {
	prefix, err := c.br.ReadByte()
	if err != nil {
		return nil, err
	}
	line, err := c.readLine()
	if err != nil {
		return nil, err
	}
	switch prefix {
	case '+':
		return line, nil
	case '-':
		return nil, errors.New("redis: " + line)
	case ':':
		n, err := strconv.ParseInt(line, 10, 64)
		if err != nil {
			return nil, err
		}
		return n, nil
	case '$':
		n, err := strconv.Atoi(line)
		if err != nil {
			return nil, err
		}
		if n < 0 {
			return nil, nil
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(c.br, buf); err != nil {
			return nil, err
		}
		return string(buf[:n]), nil
	case '*':
		n, err := strconv.Atoi(line)
		if err != nil {
			return nil, err
		}
		if n < 0 {
			return nil, nil
		}
		arr := make([]any, 0, n)
		for i := 0; i < n; i++ {
			v, err := c.readReply()
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		return arr, nil
	default:
		return nil, fmt.Errorf("redis: unknown reply prefix %q", prefix)
	}
}

func (c *redisConn) readLine() (string, error) {
	line, err := c.br.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return "", errors.New("redis: malformed reply line")
	}
	return line[:len(line)-2], nil
}

func (c *redisConn) close() {
	_ = c.nc.Close()
}
