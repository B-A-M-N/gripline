package main

import (
	"net"
	"testing"
	"time"
)

func TestLimitedListenerClosesConnectionsOverCap(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	limited := newLimitedListener(inner, 1)
	defer limited.Close()

	firstClient, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer firstClient.Close()
	firstServer, err := limited.Accept()
	if err != nil {
		t.Fatal(err)
	}

	secondClient, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer secondClient.Close()
	accepted := make(chan error, 1)
	go func() {
		conn, acceptErr := limited.Accept()
		if conn != nil {
			_ = conn.Close()
		}
		accepted <- acceptErr
	}()

	_ = secondClient.SetReadDeadline(time.Now().Add(time.Second))
	var probe [1]byte
	if _, readErr := secondClient.Read(probe[:]); readErr == nil {
		t.Fatal("connection over the configured cap remained open")
	}

	// Closing the accepted connection releases the slot; the accept loop must
	// then admit the next connection rather than permanently rejecting traffic.
	if err := firstServer.Close(); err != nil {
		t.Fatal(err)
	}
	thirdClient, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer thirdClient.Close()
	select {
	case acceptErr := <-accepted:
		if acceptErr != nil {
			t.Fatalf("replacement connection was not accepted: %v", acceptErr)
		}
	case <-time.After(time.Second):
		t.Fatal("replacement connection was not accepted after slot release")
	}
}
