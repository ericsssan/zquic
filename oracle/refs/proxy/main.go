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
// It also optionally injects seeded loss/delay, replacing tc-netem. The seed
// fixes the drop *sequence* per direction, but which logical QUIC packet lands at
// the Nth datagram still depends on endpoint timing (coalescing, PTO) — so loss
// is reproducible-sequence, not outcome-deterministic. See harness issue #8.
//
//	proxy -listen :PORT -target HOST:PORT -capture FILE [-loss PCT -corrupt PCT -delayms MS -seed N]
//
// Capture: one line PER DATAGRAM ("c2s DGRAM N") for byte-counting, followed
// by one line per QUIC packet within that datagram ("c2s CLASS N"). CLASS is
// from classifyAll. The DGRAM line lets byte-count checks (e.g. amplificationlimit)
// avoid double-counting coalesced packets. Recorded before any simulated drop/corrupt.
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

type pktClass struct {
	label  string
	length int // bytes this packet occupies in the datagram
}

// classifyAll walks coalesced QUIC packets in one UDP datagram and returns the
// type and per-packet byte length of each. Returns a best-effort list; stops at
// the first unparseable point. For packet types with no Length field (SHORT,
// RETRY, VERSION_NEGOTIATION) the length is the remaining datagram bytes.
func classifyAll(b []byte) []pktClass {
	var out []pktClass
	for len(b) >= 1 {
		if b[0]&0x80 == 0 {
			return append(out, pktClass{"SHORT", len(b)}) // runs to end of datagram
		}
		if len(b) < 5 {
			return append(out, pktClass{"LONG_TRUNC", len(b)})
		}
		if binary.BigEndian.Uint32(b[1:5]) == 0 {
			return append(out, pktClass{"VERSION_NEGOTIATION", len(b)})
		}
		t := (b[0] >> 4) & 0x03 // QUIC v1 long-header type
		if t == 3 {
			return append(out, pktClass{"RETRY", len(b)}) // no Length field; runs to end
		}
		// Parse header far enough to find the Length field.
		p := 5
		if p >= len(b) {
			return append(out, pktClass{"LONG_TRUNC", len(b)})
		}
		p += 1 + int(b[p]) // dcid len + dcid
		if p >= len(b) {
			return append(out, pktClass{"LONG_TRUNC", len(b)})
		}
		p += 1 + int(b[p]) // scid len + scid
		var label string
		switch t {
		case 0:
			label = "INITIAL"
			tl, n := readVarint(b[p:]) // token length + token
			if n == 0 {
				return append(out, pktClass{label, len(b)})
			}
			p += n + int(tl)
		case 1:
			label = "0RTT"
		case 2:
			label = "HANDSHAKE"
		}
		if p >= len(b) {
			return append(out, pktClass{label, len(b)})
		}
		ln, n := readVarint(b[p:]) // Length: rest of this packet
		if n == 0 {
			return append(out, pktClass{label, len(b)})
		}
		pktLen := p + n + int(ln) // header + length-varint + payload
		if pktLen > len(b) || pktLen <= 0 {
			return append(out, pktClass{label, len(b)})
		}
		out = append(out, pktClass{label, pktLen})
		b = b[pktLen:]
	}
	return out
}

func main() {
	listen := flag.String("listen", "", "listen addr, e.g. 127.0.0.1:4500")
	target := flag.String("target", "", "server addr, e.g. 127.0.0.1:4433")
	capture := flag.String("capture", "", "capture file path")
	loss := flag.Int("loss", 0, "loss percent [0..100]")
	corrupt := flag.Int("corrupt", 0, "corrupt percent [0..100]: bit-flip one byte in that fraction of forwarded packets (skips header type byte; AEAD detects corruption)")
	delayms := flag.Int("delayms", 0, "one-way delay in ms")
	seed := flag.Int64("seed", 42, "PRNG seed for a reproducible loss sequence")
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
	record := func(dir string, b []byte) {
		if capFile == nil {
			return
		}
		// One DGRAM line per datagram for byte-count checks (amplificationlimit).
		// Followed by one CLASS line per QUIC packet found in the datagram.
		// write(2) is immediately visible to readers; no fsync needed.
		fmt.Fprintf(capFile, "%s DGRAM %d\n", dir, len(b))
		for _, c := range classifyAll(b) {
			fmt.Fprintf(capFile, "%s %s %d\n", dir, c.label, c.length)
		}
	}
	// maybecorrupt returns a bit-flipped copy at the configured rate (using the
	// same per-direction RNG as drop, after the drop decision). Skips byte 0
	// (header type byte) so the packet is still routed correctly by the receiver
	// before AEAD rejects it. Returns the original slice if no corruption.
	maybecorrupt := func(r *rand.Rand, b []byte) []byte {
		if *corrupt <= 0 || r.Intn(100) >= *corrupt || len(b) < 2 {
			return b
		}
		c := append([]byte(nil), b...)
		c[1+r.Intn(len(c)-1)] ^= 0x01
		return c
	}
	// One PRNG per direction (each driven by a single goroutine) so the drop
	// sequence is race-free AND reproducible for a given seed. (Which logical
	// packet is the Nth datagram still varies with timing — see #8; the harness
	// keeps loss rates with headroom and offers a repeat-stability check.)
	rngC := rand.New(rand.NewSource(*seed))
	rngS := rand.New(rand.NewSource(*seed + 1))
	drop := func(r *rand.Rand) bool { return *loss > 0 && r.Intn(100) < *loss }
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
			if ca := getClient(); ca != nil && !drop(rngS) {
				fwd(func(p []byte) { front.WriteTo(p, ca) }, maybecorrupt(rngS, pkt))
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
		if !drop(rngC) {
			fwd(func(p []byte) { back.Write(p) }, maybecorrupt(rngC, pkt))
		}
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "proxy:", err)
		os.Exit(1)
	}
}
