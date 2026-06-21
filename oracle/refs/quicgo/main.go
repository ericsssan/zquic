// quic-go oracle endpoint for the zquic oracle harness.
//
// Speaks ALPN "hq-interop" (HTTP/0.9: "GET /path\r\n" -> file bytes), matching
// zquic's transfer testcase. Two modes:
//
//	quicgo client <outdir> <url>...      download each url, save to outdir/basename
//	quicgo server <addr:port> <cert> <key> <wwwdir>
//
// Exits non-zero on any failure so the harness can assert pass/fail.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const alpn = "hq-interop"

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "quicgo: "+format+"\n", a...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		fatal("usage: quicgo client|server ...")
	}
	switch os.Args[1] {
	case "client":
		runClient(os.Args[2:])
	case "server":
		runServer(os.Args[2:])
	default:
		fatal("unknown mode %q", os.Args[1])
	}
}

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	caFile := fs.String("ca", "", "PEM CA to verify the server cert; empty = skip verification")
	useV2 := fs.Bool("v2", false, "use QUIC v2 (RFC 9369) instead of v1")
	useResumption := fs.Bool("resumption", false, "make two sequential connections; second resumes with session ticket (PSK)")
	noClose := fs.Bool("no-close", false, "exit without sending CONNECTION_CLOSE (lets server's idle timer fire)")
	_ = fs.Parse(args)
	rest := fs.Args()
	if len(rest) < 2 {
		fatal("usage: quicgo client [-ca file] [-v2] [-resumption] [-no-close] <outdir> <url>...")
	}
	outdir, urls := rest[0], rest[1:]

	// All requests share one connection (matches interop multiplexing tests).
	host := ""
	for _, u := range urls {
		pu, err := url.Parse(u)
		if err != nil {
			fatal("bad url %q: %v", u, err)
		}
		host = pu.Host
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Verify the server certificate against a CA when one is supplied — this is
	// what makes the handshake a real oracle for zquic's TLS auth output, not
	// just its key schedule. With no -ca, fall back to skip-verify.
	tlsConf := &tls.Config{NextProtos: []string{alpn}}
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		if err != nil {
			fatal("read ca %s: %v", *caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			fatal("no certs parsed from %s", *caFile)
		}
		tlsConf.RootCAs = pool
	} else {
		tlsConf.InsecureSkipVerify = true
	}

	// Session cache shared across connections — enables ticket resumption on
	// the second DialAddr call without any extra client-side bookkeeping.
	tlsConf.ClientSessionCache = tls.NewLRUClientSessionCache(4)

	quicConf := &quic.Config{}
	if *useV2 {
		quicConf.Versions = []quic.Version{quic.Version2}
	}

	if *useResumption {
		// Connection 1: download first URL, let the NST arrive and be cached.
		if len(urls) < 2 {
			fatal("resumption requires at least 2 URLs")
		}
		conn1, err := quic.DialAddr(ctx, host, tlsConf, quicConf)
		if err != nil {
			fatal("dial %s (conn1): %v", host, err)
		}
		if err := fetch(ctx, conn1, urls[0], outdir); err != nil {
			fatal("conn1: %v", err)
		}
		// Wait for the NewSessionTicket to arrive before closing. NST is sent
		// post-handshake; CloseWithError discards in-flight CRYPTO frames, so
		// without this drain the session cache stays empty and conn2 falls back
		// to a full handshake, making the resumption assertion below vacuous (#25).
		time.Sleep(50 * time.Millisecond)
		conn1.CloseWithError(0, "done")

		// Connection 2: same tlsConf → session cache hit → PSK resumption.
		conn2, err := quic.DialAddr(ctx, host, tlsConf, quicConf)
		if err != nil {
			fatal("dial %s (conn2): %v", host, err)
		}
		if !conn2.ConnectionState().TLS.DidResume {
			fatal("conn2: session was not resumed — server did not issue a ticket or PSK was rejected")
		}
		defer conn2.CloseWithError(0, "done")
		var wg sync.WaitGroup
		var mu sync.Mutex
		var firstErr error
		for _, u := range urls[1:] {
			wg.Add(1)
			go func(u string) {
				defer wg.Done()
				if err := fetch(ctx, conn2, u, outdir); err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
				}
			}(u)
		}
		wg.Wait()
		if firstErr != nil {
			fatal("%v", firstErr)
		}
		return
	}

	conn, err := quic.DialAddr(ctx, host, tlsConf, quicConf)
	if err != nil {
		fatal("dial %s: %v", host, err)
	}
	if !*noClose {
		defer conn.CloseWithError(0, "done")
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	for _, u := range urls {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			if err := fetch(ctx, conn, u, outdir); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}(u)
	}
	wg.Wait()
	if firstErr != nil {
		fatal("%v", firstErr)
	}
	if *noClose {
		// Exit without running defers so the QUIC connection is not closed.
		// context.WithCancel and CloseWithError would both send CONNECTION_CLOSE,
		// preventing the server's idle timer from firing.
		os.Exit(0)
	}
}

func fetch(ctx context.Context, conn *quic.Conn, u, outdir string) error {
	pu, err := url.Parse(u)
	if err != nil {
		return err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	if _, err := fmt.Fprintf(stream, "GET %s\r\n", pu.Path); err != nil {
		return fmt.Errorf("write request: %w", err)
	}
	stream.Close() // FIN: request complete

	body, err := io.ReadAll(stream)
	if err != nil {
		return fmt.Errorf("read %s: %w", pu.Path, err)
	}
	out := filepath.Join(outdir, filepath.Base(pu.Path))
	if err := os.WriteFile(out, body, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", out, err)
	}
	return nil
}

func runServer(args []string) {
	if len(args) < 4 {
		fatal("usage: quicgo server <addr:port> <cert> <key> <wwwdir>")
	}
	addr, certFile, keyFile, wwwdir := args[0], args[1], args[2], args[3]

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		fatal("load cert: %v", err)
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{alpn},
	}
	quicConf := &quic.Config{}

	// RESET_KEY (64 hex chars = 32 bytes): configure stateless reset via Transport (#42).
	// When set, a new server instance with the same key can issue stateless resets for
	// connections it doesn't recognise — allows oracle to test client-side detection.
	var ln *quic.Listener
	if keyHex := os.Getenv("RESET_KEY"); len(keyHex) == 64 {
		keyBytes, hexErr := hex.DecodeString(keyHex)
		if hexErr == nil {
			var k quic.StatelessResetKey
			copy(k[:], keyBytes)
			udpAddr, resolveErr := net.ResolveUDPAddr("udp", addr)
			if resolveErr != nil {
				fatal("resolve %s: %v", addr, resolveErr)
			}
			conn, listenErr := net.ListenUDP("udp", udpAddr)
			if listenErr != nil {
				fatal("listen %s: %v", addr, listenErr)
			}
			tr := &quic.Transport{Conn: conn, StatelessResetKey: &k}
			var trErr error
			ln, trErr = tr.Listen(tlsConf, quicConf)
			if trErr != nil {
				fatal("listen %s: %v", addr, trErr)
			}
			fmt.Printf("[RST_KEY] stateless reset key configured\n")
		}
	}
	if ln == nil {
		var listenErr error
		ln, listenErr = quic.ListenAddr(addr, tlsConf, quicConf)
		if listenErr != nil {
			fatal("listen %s: %v", addr, listenErr)
		}
	}
	fmt.Printf("quicgo server listening on %s\n", addr)

	ctx := context.Background()
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			fatal("accept: %v", err)
		}
		go serveConn(ctx, conn, wwwdir)
	}
}

func serveConn(ctx context.Context, conn *quic.Conn, wwwdir string) {
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return // connection closed
		}
		go func() {
			line, err := bufio.NewReader(stream).ReadString('\n')
			if err != nil {
				stream.Close()
				return
			}
			// "GET /path\r\n" — Go's %s stops at \r (isSpace includes \r), so path
			// is already clean. TrimRight is defensive in case that ever changes.
			var path string
			fmt.Sscanf(line, "GET %s", &path)
			path = strings.TrimRight(path, "\r")
			// Stream the file rather than ReadFile: sparse 2GB test files would
			// OOM a ReadFile call on CI runners.
			f, err := os.Open(filepath.Join(wwwdir, filepath.Base(path)))
			if err != nil {
				stream.CancelWrite(1) // signal an error rather than a silent 0-byte body
				return
			}
			defer f.Close()
			io.Copy(stream, f) //nolint:errcheck
			stream.Close()
		}()
	}
}
