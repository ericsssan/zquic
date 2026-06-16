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
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
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
	if len(args) < 2 {
		fatal("usage: quicgo client <outdir> <url>...")
	}
	outdir, urls := args[0], args[1:]

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

	conn, err := quic.DialAddr(ctx, host, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{alpn},
	}, &quic.Config{})
	if err != nil {
		fatal("dial %s: %v", host, err)
	}
	defer conn.CloseWithError(0, "done")

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
}

func fetch(ctx context.Context, conn quic.Connection, u, outdir string) error {
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
	ln, err := quic.ListenAddr(addr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{alpn},
	}, &quic.Config{})
	if err != nil {
		fatal("listen %s: %v", addr, err)
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

func serveConn(ctx context.Context, conn quic.Connection, wwwdir string) {
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
			// "GET /path\r\n"
			var path string
			fmt.Sscanf(line, "GET %s", &path)
			data, err := os.ReadFile(filepath.Join(wwwdir, filepath.Base(path)))
			if err == nil {
				stream.Write(data)
			}
			stream.Close()
		}()
	}
}
