// Capturing UDP relay for the zquic oracle harness.
//
// Sits between an interop client and server on localhost so behavioral test
// cases can be validated against what actually appeared ON THE WIRE, not just
// "the file transferred". The QUIC long-header packet TYPE (bits 4-5 of the
// first byte) is NOT covered by header protection, so Retry / VersionNegotiation
// / 0-RTT / Initial / Handshake are classifiable in cleartext without any keys.
//
// It also (optionally) injects deterministic loss/delay, replacing tc-netem for
// the loss/RTT cases.
//
//	proxy -listen :PORT -target HOST:PORT -capture FILE [-loss PCT -delayms MS -seed N]
//
// Capture file: one line per datagram, "<c2s|s2c> <CLASS> <bytes>".
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"
)

func classify(b []byte) string {
	if len(b) < 1 {
		return "EMPTY"
	}
	if b[0]&0x80 == 0 {
		return "SHORT" // 1-RTT short header
	}
	if len(b) < 5 {
		return "LONG_TRUNC"
	}
	if binary.BigEndian.Uint32(b[1:5]) == 0 {
		return "VERSION_NEGOTIATION"
	}
	switch (b[0] >> 4) & 0x03 { // QUIC v1 long-header type (unmasked by HP)
	case 0:
		return "INITIAL"
	case 1:
		return "0RTT"
	case 2:
		return "HANDSHAKE"
	default:
		return "RETRY"
	}
}

func main() {
	listen := flag.String("listen", "", "listen addr, e.g. :4500")
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

	var cap *os.File
	if *capture != "" {
		cap, err = os.Create(*capture)
		must(err)
		defer cap.Close()
	}
	rng := rand.New(rand.NewSource(*seed))
	record := func(dir string, b []byte) {
		if cap != nil {
			fmt.Fprintf(cap, "%s %s %d\n", dir, classify(b), len(b))
			cap.Sync()
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

	// server <- back -> reads server replies; front holds the client addr.
	var clientAddr net.Addr
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := back.Read(buf)
			if err != nil {
				return
			}
			pkt := append([]byte(nil), buf[:n]...)
			record("s2c", pkt)
			if clientAddr != nil && !drop() {
				fwd(func(p []byte) { front.WriteTo(p, clientAddr) }, pkt)
			}
		}
	}()

	buf := make([]byte, 2048)
	for {
		n, addr, err := front.ReadFrom(buf)
		if err != nil {
			return
		}
		clientAddr = addr
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
