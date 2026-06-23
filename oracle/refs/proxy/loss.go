// Outcome-deterministic seeded loss for the oracle proxy (harness issue #8).
//
// The default proxy drops the Nth datagram by a seeded RNG. WHICH logical QUIC
// packet is the Nth datagram shifts with endpoint timing (coalescing, PTO, ACK
// interleaving), so the seed fixes the drop *sequence* but not the *outcome* —
// the same seed sometimes loses a recovery-critical packet and sometimes does
// not, making transferloss/transfercorruption flaky.
//
// This module makes loss a deterministic function of the STREAM DATA itself.
// Using the server's SSLKEYLOGFILE it decrypts each server->client 1-RTT packet,
// reads the first STREAM frame's offset, and impairs the FIRST transmission of a
// seeded subset of offsets (recording each so retransmissions pass through). The
// same byte ranges are therefore lost exactly once on every run regardless of
// timing — a deterministic, recoverable loss pattern. Scope: server->client,
// AES-128-GCM, key phases 0/1 (the transferloss/transfercorruption default).
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"os"
	"strings"
	"sync"
)

// ---- key schedule (RFC 9001 §5) -------------------------------------------

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

func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	full := "tls13 " + label
	info := make([]byte, 2+1+len(full)+1)
	info[0] = byte(length >> 8)
	info[1] = byte(length)
	info[2] = byte(len(full))
	copy(info[3:], full)
	return hkdfExpand(secret, info, length)
}

type appKeys struct {
	iv   []byte
	hp   []byte
	aead cipher.AEAD
}

func deriveAppKeys(secret []byte) *appKeys {
	key := hkdfExpandLabel(secret, "quic key", 16)
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil
	}
	return &appKeys{
		iv:   hkdfExpandLabel(secret, "quic iv", 12),
		hp:   hkdfExpandLabel(secret, "quic hp", 16),
		aead: aead,
	}
}

// detLoss holds deterministic-loss state for the server->client direction.
type detLoss struct {
	mu         sync.Mutex
	keylog     string
	pct        int
	seed       uint64
	s2cDCIDLen int // DCID length in s2c SHORT packets (= client SCID len)
	gen0, gen1 *appKeys
	largestPN  uint64
	dropped    map[uint64]bool // stream offsets already impaired once
	decrypted  uint64          // diagnostics: packets successfully decrypted
	hit        uint64          // diagnostics: packets impaired
}

func newDetLoss(keylog string, pct int, seed int64) *detLoss {
	return &detLoss{keylog: keylog, pct: pct, seed: uint64(seed), s2cDCIDLen: -1, dropped: map[uint64]bool{}}
}

// observeC2SInitial learns the client's SCID length from the first c2s INITIAL,
// which is the DCID length the server stamps on its SHORT-header packets.
func (d *detLoss) observeC2SInitial(dgram []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.s2cDCIDLen >= 0 || len(dgram) < 7 || dgram[0]&0x80 == 0 {
		return
	}
	if binary.BigEndian.Uint32(dgram[1:5]) == 0 { // version negotiation
		return
	}
	if (dgram[0]>>4)&0x03 != 0 { // not INITIAL
		return
	}
	dcidLen := int(dgram[5])
	scidOff := 6 + dcidLen
	if scidOff < len(dgram) {
		d.s2cDCIDLen = int(dgram[scidOff])
	}
}

func (d *detLoss) ensureKeys() bool {
	if d.gen0 != nil {
		return true
	}
	secret := readServerSecret(d.keylog)
	if secret == nil {
		return false
	}
	d.gen0 = deriveAppKeys(secret)
	// gen-1 covers a single peer-initiated key update mid-transfer.
	d.gen1 = deriveAppKeys(hkdfExpandLabel(secret, "quic ku", 32))
	if d.gen0 != nil {
		fmt.Fprintln(os.Stderr, "det-loss: s2c 1-RTT keys derived from keylog")
	}
	return d.gen0 != nil
}

// readServerSecret returns SERVER_TRAFFIC_SECRET_0 from the keylog (gen-0 1-RTT
// secret), or nil if not present yet.
func readServerSecret(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var secret []byte
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[0] == "SERVER_TRAFFIC_SECRET_0" {
			if b, err := hex.DecodeString(f[2]); err == nil {
				secret = b
			}
		}
	}
	return secret
}

// decodePN reconstructs the full packet number (RFC 9000 §A.3).
func decodePN(largest, trunc uint64, pnLen int) uint64 {
	win := uint64(1) << (uint(pnLen) * 8)
	hwin := win / 2
	expected := largest + 1
	cand := (expected &^ (win - 1)) | trunc
	if cand+hwin <= expected && cand+win < (uint64(1)<<62) {
		cand += win
	} else if cand > expected+hwin && cand >= win {
		cand -= win
	}
	return cand
}

// shouldImpairS2C decrypts an s2c SHORT-header datagram, finds the first STREAM
// frame's offset, and returns true if this datagram should be dropped/corrupted
// (offset selected by the seed and not yet impaired). Fail-open: returns false
// (forward) for anything it cannot classify — handshake packets, keys not ready,
// no stream data, or a decryption failure — so a crypto problem never corrupts
// the transfer, it just disables the impairment.
func (d *detLoss) shouldImpairS2C(dgram []byte) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.s2cDCIDLen < 0 || len(dgram) < 1 || dgram[0]&0x80 != 0 {
		return false // not a SHORT-header (1-RTT) packet
	}
	if !d.ensureKeys() {
		return false
	}
	pnOff := 1 + d.s2cDCIDLen
	if pnOff+4+16 > len(dgram) {
		return false
	}
	sample := dgram[pnOff+4 : pnOff+4+16] // header-protection sample
	// Key phase is itself protected, so try gen-0 then gen-1.
	for _, ks := range []*appKeys{d.gen0, d.gen1} {
		if ks == nil {
			continue
		}
		blk, _ := aes.NewCipher(ks.hp)
		mask := make([]byte, 16)
		blk.Encrypt(mask, sample)
		fb := dgram[0] ^ (mask[0] & 0x1f)
		pnLen := int(fb&0x03) + 1
		hdr := make([]byte, pnOff+pnLen)
		copy(hdr, dgram[:pnOff+pnLen])
		hdr[0] = fb
		var trunc uint64
		for i := 0; i < pnLen; i++ {
			hdr[pnOff+i] = dgram[pnOff+i] ^ mask[1+i]
			trunc = (trunc << 8) | uint64(hdr[pnOff+i])
		}
		pn := decodePN(d.largestPN, trunc, pnLen)
		nonce := make([]byte, 12)
		copy(nonce, ks.iv)
		var pn8 [8]byte
		binary.BigEndian.PutUint64(pn8[:], pn)
		for i := 0; i < 8; i++ {
			nonce[4+i] ^= pn8[i]
		}
		pt, err := ks.aead.Open(nil, nonce, dgram[pnOff+pnLen:], hdr)
		if err != nil {
			continue // wrong key phase or not ours
		}
		d.decrypted++
		if pn > d.largestPN {
			d.largestPN = pn
		}
		off, ok := firstStreamOffset(pt)
		if !ok || !d.selected(off) || d.dropped[off] {
			return false
		}
		d.dropped[off] = true
		d.hit++
		fmt.Fprintf(os.Stderr, "det-loss: impair s2c offset=%d (decrypted=%d hit=%d)\n", off, d.decrypted, d.hit)
		return true
	}
	return false
}

func (d *detLoss) selected(offset uint64) bool {
	h := fnv.New64a()
	var b [16]byte
	binary.LittleEndian.PutUint64(b[0:8], d.seed)
	binary.LittleEndian.PutUint64(b[8:16], offset)
	h.Write(b[:])
	return int(h.Sum64()%100) < d.pct
}

// lossReadVarint decodes a QUIC variable-length integer; returns value and len.
func lossReadVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = (v << 8) | uint64(b[i])
	}
	return v, n
}

// firstStreamOffset walks decrypted 1-RTT frames and returns the offset of the
// first STREAM frame, properly skipping PADDING/PING/ACK. Bails (false) on any
// frame it cannot advance past, so it never mis-attributes an offset.
func firstStreamOffset(p []byte) (uint64, bool) {
	i := 0
	rd := func() (uint64, bool) {
		v, n := lossReadVarint(p[i:])
		if n == 0 {
			return 0, false
		}
		i += n
		return v, true
	}
	for i < len(p) {
		ft := p[i]
		i++
		switch {
		case ft == 0x00 || ft == 0x01: // PADDING / PING
			continue
		case ft == 0x02 || ft == 0x03: // ACK / ACK_ECN
			if _, ok := rd(); !ok { // largest_acked
				return 0, false
			}
			if _, ok := rd(); !ok { // ack_delay
				return 0, false
			}
			rangeCount, ok := rd()
			if !ok {
				return 0, false
			}
			if _, ok := rd(); !ok { // first_ack_range
				return 0, false
			}
			for r := uint64(0); r < rangeCount; r++ {
				if _, ok := rd(); !ok { // gap
					return 0, false
				}
				if _, ok := rd(); !ok { // ack_range_length
					return 0, false
				}
			}
			if ft == 0x03 { // ECN counts: ect0, ect1, ce
				for k := 0; k < 3; k++ {
					if _, ok := rd(); !ok {
						return 0, false
					}
				}
			}
		case ft >= 0x08 && ft <= 0x0f: // STREAM
			if _, ok := rd(); !ok { // stream_id
				return 0, false
			}
			var off uint64
			if ft&0x04 != 0 { // OFF bit set
				v, ok := rd()
				if !ok {
					return 0, false
				}
				off = v
			}
			return off, true
		default:
			return 0, false // unknown frame; stop to avoid mis-parsing
		}
	}
	return 0, false
}
