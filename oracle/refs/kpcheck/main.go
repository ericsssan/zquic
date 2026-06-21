// kpcheck: QUIC Key Phase bit wire-proof tool (#40).
//
// Reads an SSLKEYLOGFILE and a SHORT-packet hex dump (from proxy -shorts) and
// verifies that the QUIC Key Phase bit (bit 2 of the unprotected first byte)
// flips at least once — proving a key update happened on wire, not just in logs.
//
// Header protection is removed per RFC 9001 §5.4:
//   hp_key = HKDF-Expand-Label(traffic_secret_0, "quic hp", "", 16)
//   sample = pkt[1+dcid_len+4 : 1+dcid_len+20]   (16 bytes)
//   mask   = AES-128-ECB(hp_key, sample)
//   first  = pkt[0] ^ (mask[0] & 0x1F)
//   kp_bit = (first >> 2) & 1
//
// The hp_key does NOT change across key updates (RFC 9001 §6.5), so generation-0
// secrets suffice for every SHORT packet in the connection.
//
// Usage:
//   kpcheck -keylog <file> -shorts <file>
//
// Exits 0 on success (KP bit flipped), 1 on failure (no flip / error).
package main

import (
	"bufio"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// hkdfExpand implements HKDF-Expand (RFC 5869 §2.3) with SHA-256.
// Returns the first `length` bytes of the OKM.
func hkdfExpand(prk, info []byte, length int) []byte {
	out := make([]byte, 0, length)
	prev := []byte{}
	for i := 1; len(out) < length; i++ {
		h := hmac.New(sha256.New, prk)
		h.Write(prev)
		h.Write(info)
		h.Write([]byte{byte(i)})
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:length]
}

// hkdfExpandLabel implements HKDF-Expand-Label (RFC 8446 §3.4 / RFC 9001 §5.1).
// label is the short label (without "tls13 " prefix); length is the desired key length.
func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	// HkdfLabel: uint16 length || uint8 label_len || "tls13 " || label || uint8 0 (empty context)
	fullLabel := "tls13 " + label
	info := make([]byte, 2+1+len(fullLabel)+1)
	info[0] = byte(length >> 8)
	info[1] = byte(length)
	info[2] = byte(len(fullLabel))
	copy(info[3:], fullLabel)
	info[3+len(fullLabel)] = 0 // empty context
	return hkdfExpand(secret, info, length)
}

// deriveHPKey derives the QUIC header protection key from a traffic secret.
func deriveHPKey(trafficSecret []byte) []byte {
	return hkdfExpandLabel(trafficSecret, "quic hp", 16)
}

// removeShorHeaderProtection removes header protection from one SHORT packet and
// returns the unprotected first byte. dcidLen is the DCID length in this packet.
// Returns -1 if the packet is too short.
func removeShortHeaderProtection(pkt []byte, hpKey []byte, dcidLen int) int {
	sampleOffset := 1 + dcidLen + 4
	if sampleOffset+16 > len(pkt) {
		return -1
	}
	sample := pkt[sampleOffset : sampleOffset+16]
	block, err := aes.NewCipher(hpKey)
	if err != nil {
		return -1
	}
	mask := make([]byte, 16)
	block.Encrypt(mask, sample)
	// Short header: mask bits 4..0 of first byte (0x1F).
	return int(pkt[0] ^ (mask[0] & 0x1F))
}

type shortPacket struct {
	dir string
	raw []byte
}

func main() {
	keylogFile := flag.String("keylog", "", "SSLKEYLOGFILE path (written by zquic server)")
	shortsFile := flag.String("shorts", "", "SHORT packet hex dump from proxy -shorts flag")
	flag.Parse()

	if *keylogFile == "" || *shortsFile == "" {
		fmt.Fprintln(os.Stderr, "kpcheck: -keylog and -shorts required")
		os.Exit(1)
	}

	// Parse SSLKEYLOGFILE: extract CLIENT_TRAFFIC_SECRET_0 and SERVER_TRAFFIC_SECRET_0.
	clientSecret, serverSecret, err := parseKeyLog(*keylogFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kpcheck: keylog: %v\n", err)
		os.Exit(1)
	}

	// Parse shorts file: read DCID lengths header and SHORT packet bytes.
	c2sDCID, s2cDCID, pkts, err := parseShortsFile(*shortsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kpcheck: shorts: %v\n", err)
		os.Exit(1)
	}
	if len(pkts) == 0 {
		fmt.Fprintln(os.Stderr, "kpcheck: no SHORT packets in dump")
		os.Exit(1)
	}

	// Derive header protection keys (do NOT change across key updates — RFC 9001 §6.5).
	clientHP := deriveHPKey(clientSecret)
	serverHP := deriveHPKey(serverSecret)

	// Remove HP from each SHORT packet and collect KP bit values per direction.
	kpSeen := map[string]map[int]int{"c2s": {}, "s2c": {}}
	for _, p := range pkts {
		dcidLen := c2sDCID
		hpKey := clientHP
		if p.dir == "s2c" {
			dcidLen = s2cDCID
			hpKey = serverHP
		}
		first := removeShortHeaderProtection(p.raw, hpKey, dcidLen)
		if first < 0 {
			continue
		}
		kpBit := (first >> 2) & 1
		kpSeen[p.dir][kpBit]++
	}

	// Assert: at least one direction has both KP=0 and KP=1 packets.
	for dir, counts := range kpSeen {
		if counts[0] > 0 && counts[1] > 0 {
			fmt.Printf("kpcheck: PASS — %s KP bit flipped (phase0=%d phase1=%d)\n",
				dir, counts[0], counts[1])
			os.Exit(0)
		}
	}

	// Failure: print what was observed.
	for dir, counts := range kpSeen {
		fmt.Printf("kpcheck: %s phase0=%d phase1=%d\n", dir, counts[0], counts[1])
	}
	fmt.Fprintln(os.Stderr, "kpcheck: FAIL — Key Phase bit never flipped on wire")
	os.Exit(1)
}

// parseKeyLog scans an SSLKEYLOGFILE and returns (clientSecret, serverSecret).
func parseKeyLog(path string) ([]byte, []byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	var clientSec, serverSec []byte
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 3 {
			continue
		}
		label, _, secretHex := parts[0], parts[1], parts[2]
		secret, err := hex.DecodeString(secretHex)
		if err != nil {
			continue
		}
		switch label {
		case "CLIENT_TRAFFIC_SECRET_0":
			clientSec = secret
		case "SERVER_TRAFFIC_SECRET_0":
			serverSec = secret
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, err
	}
	if clientSec == nil {
		return nil, nil, fmt.Errorf("CLIENT_TRAFFIC_SECRET_0 not found")
	}
	if serverSec == nil {
		return nil, nil, fmt.Errorf("SERVER_TRAFFIC_SECRET_0 not found")
	}
	return clientSec, serverSec, nil
}

// parseShortsFile reads the proxy -shorts output: a header followed by hex packet lines.
func parseShortsFile(path string) (c2sDCID, s2cDCID int, pkts []shortPacket, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, nil, err
	}
	defer f.Close()

	c2sDCID, s2cDCID = -1, -1
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) == 2 {
			switch parts[0] {
			case "c2s-dcid-len":
				if n, e := strconv.Atoi(parts[1]); e == nil {
					c2sDCID = n
				}
				continue
			case "s2c-dcid-len":
				if n, e := strconv.Atoi(parts[1]); e == nil {
					s2cDCID = n
				}
				continue
			case "c2s", "s2c":
				raw, e := hex.DecodeString(parts[1])
				if e == nil && len(raw) > 0 {
					pkts = append(pkts, shortPacket{dir: parts[0], raw: raw})
				}
				continue
			}
		}
	}
	if err = sc.Err(); err != nil {
		return 0, 0, nil, err
	}
	if c2sDCID < 0 {
		return 0, 0, nil, fmt.Errorf("c2s-dcid-len header not found")
	}
	if s2cDCID < 0 {
		return 0, 0, nil, fmt.Errorf("s2c-dcid-len header not found")
	}
	return c2sDCID, s2cDCID, pkts, nil
}
