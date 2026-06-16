// Capturing UDP relay for the zquic oracle harness.
//
// Sits between an interop client and server on localhost so behavioral test
// cases can be validated against what actually appeared ON THE WIRE, not just
// "the file transferred". QUIC long-header packet TYPEs (bits 4-5 of the first
// byte) are NOT covered by header protection, so Retry / VersionNegotiation /
// 0-RTT / Initial / Handshake are classifiable in cleartext without any keys.
// Coalesced packets in one datagram are walked individually (via the long-header
// Length field), so a 0-RTT coalesced after an Initial is still seen.
//
// It also optionally injects deterministic loss/delay, replacing tc-netem.
//
//	proxy -listen :PORT -target HOST:PORT -capture FILE [-loss PCT -delayms MS -seed N]
//
// Capture: one line PER QUIC packet, "<c2s|s2c> <CLASS> <datagram_bytes>".
// Recorded on receipt (what the sender transmitted), before any simulated drop.
//
// Limitation: tracks a single client flow (last sender address wins) — multi-
// connection cases (resumption/multiconnect) are out of scope.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"
)

// readVarint decodes a QUIC variable-length integer (RFC 9000 §16).
func readVarint(b []byte) (val uint64, n int) {
	if len(b) == 0 {
		return 0, 0
	}
	length := 1 << (b[0] >> 6) // 1, 2, 4, or 8 bytes
	if len(b) < length {
		return 0, 0
	}
	val = uint64(b[0] & 0x3f)
	for i := 1; i < length; i++ {
		val = (val << 8) | uint64(b[i])
	}
	return val, length
}

// classifyAll walks coalesced QUIC packets in one UDP datagram and returns the
// type of each. Returns a best-effort list; stops at the first unparseable point.
func classifyAll(b []byte) []string {
	var out []string
	for len(b) >= 1 {
		if b[0]&0x80 == 0 {
			return append(out, "SHORT") // short header runs to end of datagram
		}
		if len(b) < 5 {
			return append(out, "LONG_TRUNC")
		}
		if binary.BigEndian.Uint32(b[1:5]) == 0 {
			return append(out, "VERSION_NEGOTIATION")
		}
		t := (b[0] >> 4) & 0x03 // QUIC v1 long-header type
		if t == 3 {
			return append(out, "RETRY") // Retry has no Length; runs to end
		}
		// Parse header far enough to find the Length field.
		p := 5
		if p >= len(b) {
			return append(out, "LONG_TRUNC")
		}
		p += 1 + int(b[p]) // dcid len + dcid
		if p >= len(b) {
			return append(out, "LONG_TRUNC")
		}
		p += 1 + int(b[p]) // scid len + scid
		switch t {
		case 0:
			out = append(out, "INITIAL")
			tl, n := readVarint(b[p:]) // token length + token
			if n == 0 {
				return out
			}
			p += n + int(tl)
		case 1:
			out = append(out, "0RTT")
		case 2:
			out = append(out, "HANDSHAKE")
		}
		if p >= len(b) {
			return out
		}
		ln, n := readVarint(b[p:]) // Length: rest of this packet
		if n == 0 {
			return out
		}
		p += n + int(ln)
		if p > len(b) || p <= 0 {
			return out
		}
		b = b[p:]
	}
	return out
}

func main() {
	listen := flag.String("listen", "", "listen addr, e.g. 127.0.0.1:4500")
	target := flag.String("target", "", "server addr, e.g. 127.0.0.1:4433")
	capture := flag.String("capture", "", "capture file path")
	loss := flag.Int("loss", 0, "loss percent [0..100]")
	delayms := flag.Int("delayms", 0, "one-way delay in ms")
	seed := flag.Int64("seed", 42, "PRNG seed for deterministic loss")
	flag.Parse()
	if *listen == "" || *target == "" {
		fmt.Fprintln(os.Stderr, "proxy: -listen and -target required")
		os.Exit(2)
	}

	srvAddr, err := net.ResolveUDPAddr("udp", *target)
	must(err)
	front, err := net.ListenPacket("udp", *listen)
	must(err)
	back, err := net.DialUDP("udp", nil, srvAddr)
	must(err)

	var capFile *os.File
	if *capture != "" {
		capFile, err = os.Create(*capture)
		must(err)
		defer capFile.Close()
	}
	rng := rand.New(rand.NewSource(*seed))
	record := func(dir string, b []byte) {
		if capFile == nil {
			return
		}
		for _, c := range classifyAll(b) {
			// write(2) is immediately visible to a reader in another process;
			// no fsync needed for the harness to grep the capture.
			fmt.Fprintf(capFile, "%s %s %d\n", dir, c, len(b))
		}
	}
	drop := func() bool { return *loss > 0 && rng.Intn(100) < *loss }
	fwd := func(send func([]byte), b []byte) {
		if *delayms > 0 {
			time.AfterFunc(time.Duration(*delayms)*time.Millisecond, func() { send(b) })
		} else {
			send(b)
		}
	}

	var mu sync.Mutex
	var clientAddr net.Addr
	getClient := func() net.Addr { mu.Lock(); defer mu.Unlock(); return clientAddr }
	setClient := func(a net.Addr) { mu.Lock(); clientAddr = a; mu.Unlock() }

	// Server replies (back) -> client (front).
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := back.Read(buf)
			if err != nil {
				return
			}
			pkt := append([]byte(nil), buf[:n]...)
			record("s2c", pkt)
			if ca := getClient(); ca != nil && !drop() {
				fwd(func(p []byte) { front.WriteTo(p, ca) }, pkt)
			}
		}
	}()

	// Client requests (front) -> server (back).
	buf := make([]byte, 65535)
	for {
		n, addr, err := front.ReadFrom(buf)
		if err != nil {
			return
		}
		setClient(addr)
		pkt := append([]byte(nil), buf[:n]...)
		record("c2s", pkt)
		if !drop() {
			fwd(func(p []byte) { back.Write(p) }, pkt)
		}
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "proxy:", err)
		os.Exit(1)
	}
}
