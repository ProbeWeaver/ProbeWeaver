package fuzzing

import (
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zmap/zgrab2"
)

// Real loopback sockets: no public targets, Docker or external certificates.
func TestTLSExecutionFacts(t *testing.T) {
	certServer := httptest.NewTLSServer(nil)
	cert := certServer.TLS.Certificates[0]
	certServer.Close()
	for _, mode := range []string{"tls", "reject", "plain"} {
		t.Run(mode, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			if mode == "tls" {
				ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MaxVersion: tls.VersionTLS12})
			}
			received := make(chan int, 1)
			payload := []byte("fixture-payload")
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					received <- -1
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				if mode == "reject" {
					_, _ = conn.Write([]byte("NOT TLS\r\n"))
					received <- 0
					return
				}
				buf := make([]byte, len(payload))
				n, _ := io.ReadFull(conn, buf)
				received <- n
				_, _ = conn.Write([]byte("fixture-response"))
			}()
			port := uint(ln.Addr().(*net.TCPAddr).Port)
			flags := &Flags{Payload: hex.EncodeToString(payload), UseTLS: mode != "plain"}
			flags.BaseFlags = zgrab2.BaseFlags{Port: port, Timeout: time.Second, BytesReadLimit: 65536}
			scanner := &Scanner{}
			if err := scanner.Init(flags); err != nil {
				t.Fatal(err)
			}
			_, raw, scanErr := scanner.Scan(zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: &port})
			result, ok := raw.(*ScanResults)
			if !ok {
				t.Fatalf("missing execution facts: %v", scanErr)
			}
			if mode == "reject" {
				if scanErr == nil || !strings.HasPrefix(scanErr.Error(), "TLS handshake failed:") {
					t.Fatalf("wrong error: %v", scanErr)
				}
				if result.TLSHandshakeStatus != "failed" || result.ApplicationPayloads != 0 || result.ApplicationPayloadBytes != 0 {
					t.Fatalf("handshake counted as payload: %+v", result)
				}
			} else {
				if scanErr != nil {
					t.Fatal(scanErr)
				}
				want := "not_requested"
				if mode == "tls" {
					want = "succeeded"
				}
				if result.TLSHandshakeStatus != want || result.ApplicationPayloads != 1 || result.ApplicationPayloadBytes != len(payload) {
					t.Fatalf("wrong execution facts: %+v", result)
				}
			}
			select {
			case n := <-received:
				if mode != "reject" && n != len(payload) {
					t.Fatalf("received %d", n)
				}
			case <-time.After(4 * time.Second):
				t.Fatal("fixture stalled")
			}
		})
	}
}

func TestRejectTLSOverUDP(t *testing.T) {
	f := &Flags{UseTLS: true, UseUDP: true, Payload: "0102"}
	if f.Validate(nil) == nil {
		t.Fatal("TLS/UDP accepted")
	}
}
