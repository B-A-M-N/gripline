package main

import (
	"net"
	"sync"
)

// limitedListener bounds accepted TCP connections before net/http allocates a
// server connection and, for TLS, before handshake/request state is created.
// Connections over the limit are closed immediately; the upstream edge/LB
// remains responsible for volumetric DDoS absorption.
type limitedListener struct {
	net.Listener
	slots chan struct{}
}

func newLimitedListener(inner net.Listener, maxConnections int) net.Listener {
	if maxConnections <= 0 {
		maxConnections = 4096
	}
	return &limitedListener{Listener: inner, slots: make(chan struct{}, maxConnections)}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &limitedConn{Conn: conn, release: func() { <-l.slots }}, nil
		default:
			_ = conn.Close()
		}
	}
}

type limitedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
