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
//	proxy -listen :PORT -target HOST:PORT -capture FILE [-loss PCT -corrupt PCT -delayms MS -seed N] [-ecn]
//
// Capture: one line PER DATAGRAM ("c2s DGRAM N") for byte-counting, followed
// by one line per QUIC packet within that datagram ("c2s CLASS N"). CLASS is
// from classifyAll. The DGRAM line lets byte-count checks (e.g. amplificationlimit)
// avoid double-counting coalesced packets. Recorded before any simulated drop/corrupt.
//
// When -ecn is set (Linux only): enables IP_RECVTOS on the back socket so that
// the IP TOS byte (containing ECN bits) of server→proxy packets is read via CMSG.
// ECN-marked packet counts are appended to the capture file as "s2c ECT0 N" etc.
// This proves server-sent packets carry ECN markings on the wire (#41).
//
// Limitation: tracks a single client flow (last sender address wins) — multi-
// connection cases (resumption/multiconnect) are out of scope.
package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"runtime"
	"sync"
	"syscall"
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
	ecnFlag := flag.Bool("ecn", false, "read IP ECN bits from s2c packets via IP_RECVTOS CMSG (Linux only) and append counts to capture file (#41)")
	shortsFlag := flag.String("shorts", "", "file path for SHORT packet hex dump used by kpcheck for KP bit wire-proof (#40)")
	tolerantBack := flag.Bool("tolerant-back", false, "retry s2c Read after errors instead of exiting (for tests where the server restarts mid-connection)")
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
		// Closed explicitly after wg.Wait() below — not via defer — so the
		// s2c goroutine cannot write to a closed file (#28).
	}
	var shortsFile *os.File
	if *shortsFlag != "" {
		shortsFile, err = os.Create(*shortsFlag)
		must(err)
	}
	// DCID lengths for SHORT packets, derived from first INITIAL packets (#40).
	// c2sDCIDLen = server SCID len (from first s2c INITIAL) = DCID in c2s SHORT packets.
	// s2cDCIDLen = client SCID len (from first c2s INITIAL) = DCID in s2c SHORT packets.
	var (
		c2sDCIDLen       = -1
		s2cDCIDLen       = -1
		shortsHdrWritten = false
	)
	var capMu sync.Mutex // serialises concurrent c2s (main) + s2c (goroutine) writes
	record := func(dir string, b []byte) {
		if capFile == nil && shortsFile == nil {
			return
		}
		capMu.Lock()
		defer capMu.Unlock()
		if capFile != nil {
			// One DGRAM line per datagram for byte-count checks (amplificationlimit).
			// Followed by one CLASS line per QUIC packet found in the datagram.
			// write(2) is immediately visible to readers; no fsync needed.
			fmt.Fprintf(capFile, "%s DGRAM %d\n", dir, len(b))
			for _, c := range classifyAll(b) {
				fmt.Fprintf(capFile, "%s %s %d\n", dir, c.label, c.length)
			}
		}
		if shortsFile != nil {
			// Walk datagram: extract SCID lengths from first INITIAL packets and
			// dump SHORT packet bytes for KP bit wire-proof (#40).
			offset := 0
			for _, c := range classifyAll(b) {
				end := offset + c.length
				if end > len(b) {
					break
				}
				pkt := b[offset:end]
				switch c.label {
				case "INITIAL":
					// Long-header INITIAL: byte 5 = DCID length, byte 6+dcidLen = SCID length.
					if len(pkt) >= 7 {
						dcidLen := int(pkt[5])
						scidOff := 6 + dcidLen
						if scidOff < len(pkt) {
							scidLen := int(pkt[scidOff])
							// client→server INITIAL: client SCID = DCID of s2c SHORT packets.
							if dir == "c2s" && s2cDCIDLen < 0 {
								s2cDCIDLen = scidLen
							}
							// server→client INITIAL: server SCID = DCID of c2s SHORT packets.
							if dir == "s2c" && c2sDCIDLen < 0 {
								c2sDCIDLen = scidLen
							}
						}
					}
				case "SHORT":
					// Write header once both DCID lengths are known, then dump SHORT bytes.
					if !shortsHdrWritten && c2sDCIDLen >= 0 && s2cDCIDLen >= 0 {
						fmt.Fprintf(shortsFile, "c2s-dcid-len %d\n", c2sDCIDLen)
						fmt.Fprintf(shortsFile, "s2c-dcid-len %d\n", s2cDCIDLen)
						shortsHdrWritten = true
					}
					if shortsHdrWritten {
						fmt.Fprintf(shortsFile, "%s %s\n", dir, hex.EncodeToString(pkt))
					}
				}
				offset = end
			}
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

	// -ecn: enable IP_RECVTOS on back socket so the IP TOS byte (ECN bits) of
	// server-sent packets is delivered as CMSG in ReadMsgUDP (#41, Linux only).
	useECN := *ecnFlag && runtime.GOOS == "linux"
	if useECN {
		if rc, e := back.SyscallConn(); e == nil {
			rc.Control(func(fd uintptr) { // IP_RECVTOS = 13 on Linux
				syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, 0xd, 1)
			})
		}
	}

	// Server replies (back) -> client (front).
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		// ECN codepoint observations for the server→proxy direction (#41).
		// Index = ECN bits (0=Not-ECT, 1=ECT(1), 2=ECT(0), 3=CE) from IP TOS.
		// Each codepoint is written to the capture the FIRST time it is seen, with
		// an immediate (durable) write(2) — not aggregated in a defer. The proxy is
		// stopped with SIGTERM (no signal handler), so a deferred flush would never
		// run and the wire-proof line would be lost even when ECN is on the wire.
		ecnLabels := [4]string{"NOT_ECT", "ECT1", "ECT0", "CE"}
		var ecnSeen [4]bool
		var oob [64]byte
		for {
			var n int
			var err error
			if useECN {
				var oobn int
				n, oobn, _, _, err = back.ReadMsgUDP(buf, oob[:])
				if err == nil && oobn > 0 {
					// Parse CMSG for IP_TOS (level=IPPROTO_IP=0, type=IP_TOS=1).
					msgs, _ := syscall.ParseSocketControlMessage(oob[:oobn])
					for _, m := range msgs {
						if m.Header.Level == syscall.IPPROTO_IP && m.Header.Type == 1 && len(m.Data) > 0 {
							idx := m.Data[0] & 0x03
							if capFile != nil && !ecnSeen[idx] {
								ecnSeen[idx] = true
								capMu.Lock()
								fmt.Fprintf(capFile, "s2c %s 1\n", ecnLabels[idx])
								capMu.Unlock()
							}
						}
					}
				}
			} else {
				n, err = back.Read(buf)
			}
			if err != nil {
				if *tolerantBack {
					time.Sleep(10 * time.Millisecond)
					continue
				}
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
			break
		}
		setClient(addr)
		pkt := append([]byte(nil), buf[:n]...)
		record("c2s", pkt)
		if !drop(rngC) {
			fwd(func(p []byte) { back.Write(p) }, maybecorrupt(rngC, pkt))
		}
	}
	// Drain the s2c goroutine before closing the capture file (#28).
	// Closing back unblocks back.Read; wg.Wait ensures the last record()
	// call completes before capFile.Close() runs.
	back.Close()
	wg.Wait()
	if capFile != nil {
		capFile.Close()
	}
	if shortsFile != nil {
		shortsFile.Close()
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "proxy:", err)
		os.Exit(1)
	}
}
