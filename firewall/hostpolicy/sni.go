package hostpolicy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"sort"
	"strings"
)

// SNIWhitelist lists the exact 9 allowed SNI hostnames for container inbound TLS/QUIC.
var SNIWhitelist = []string{
	"dl-cdn.alpinelinux.org",
	"deb.debian.org",
	"crates.io",
	"pypi.org",
	"rubygems.org",
	"addons.mozilla.org",
	"formulae.brew.sh",
	"static.rust-lang.org",
	"cpan.org",
}

type SNIParseStatus int

const (
	SNINotHandshake SNIParseStatus = iota
	SNIFound
	SNIMissing
	SNIMalformed
)

type SNIDecision struct {
	Allow  bool       `json:"allow"`
	Reason string     `json:"reason,omitempty"`
	SNI    string     `json:"sni,omitempty"`
	Proto  uint8      `json:"proto"`
	DPort  uint16     `json:"dport"`
	SrcIP  netip.Addr `json:"src_ip,omitempty"`
}

// NormalizeSNI lowercases, trims whitespace and trailing dots, and validates hostname bytes.
func NormalizeSNI(raw string) (string, bool) {
	s := strings.ToLower(strings.TrimRight(strings.TrimSpace(raw), "."))
	if len(s) == 0 || len(s) > 253 {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		ok := (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '.' || b == '-' || b == '_'
		if !ok {
			return "", false
		}
	}
	return s, true
}

// IsAllowedSNI checks whether raw SNI matches the 9-domain whitelist.
func IsAllowedSNI(raw string) bool {
	norm, ok := NormalizeSNI(raw)
	if !ok {
		return false
	}
	for _, allowed := range SNIWhitelist {
		if norm == allowed {
			return true
		}
	}
	return false
}

// ExtractTLSClientHelloSNI parses a TCP TLS Record containing a ClientHello.
func ExtractTLSClientHelloSNI(payload []byte) (string, SNIParseStatus) {
	if len(payload) < 6 {
		return "", SNINotHandshake
	}
	if payload[0] != 0x16 || payload[1] != 0x03 || payload[2] > 0x04 {
		return "", SNINotHandshake
	}
	recLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if recLen == 0 {
		return "", SNIMalformed
	}
	recEnd := 5 + recLen
	if recEnd > len(payload) {
		recEnd = len(payload)
	}
	return parseTLSHandshakeClientHelloSNI(payload[5:recEnd])
}

func parseTLSHandshakeClientHelloSNI(hs []byte) (string, SNIParseStatus) {
	if len(hs) < 4 || hs[0] != 0x01 {
		return "", SNINotHandshake
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if hsLen < 34 || 4+hsLen > len(hs) {
		return "", SNIMalformed
	}
	body := hs[4 : 4+hsLen]
	pos := 34
	if pos >= len(body) {
		return "", SNIMalformed
	}
	sidLen := int(body[pos])
	pos++
	if pos+sidLen > len(body) {
		return "", SNIMalformed
	}
	pos += sidLen
	if pos+2 > len(body) {
		return "", SNIMalformed
	}
	csLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if csLen == 0 || csLen%2 != 0 || pos+csLen > len(body) {
		return "", SNIMalformed
	}
	pos += csLen
	if pos >= len(body) {
		return "", SNIMalformed
	}
	compLen := int(body[pos])
	pos++
	if compLen == 0 || pos+compLen > len(body) {
		return "", SNIMalformed
	}
	pos += compLen
	if pos == len(body) {
		return "", SNIMissing
	}
	if pos+2 > len(body) {
		return "", SNIMalformed
	}
	extTotal := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if pos+extTotal > len(body) {
		return "", SNIMalformed
	}
	extEnd := pos + extTotal
	for pos < extEnd {
		if pos+4 > extEnd {
			return "", SNIMalformed
		}
		extType := binary.BigEndian.Uint16(body[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > extEnd {
			return "", SNIMalformed
		}
		if extType == 0x0000 {
			extData := body[pos : pos+extLen]
			if len(extData) < 2 {
				return "", SNIMalformed
			}
			listLen := int(binary.BigEndian.Uint16(extData[0:2]))
			if 2+listLen > len(extData) {
				return "", SNIMalformed
			}
			spos := 2
			send := 2 + listLen
			for spos < send {
				if spos+3 > send {
					return "", SNIMalformed
				}
				nameType := extData[spos]
				nameLen := int(binary.BigEndian.Uint16(extData[spos+1 : spos+3]))
				spos += 3
				if spos+nameLen > send {
					return "", SNIMalformed
				}
				if nameType == 0x00 {
					norm, ok := NormalizeSNI(string(extData[spos : spos+nameLen]))
					if !ok {
						return "", SNIMalformed
					}
					return norm, SNIFound
				}
				spos += nameLen
			}
			return "", SNIMissing
		}
		pos += extLen
	}
	return "", SNIMissing
}

var (
	quicV1Salt = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	quicV2Salt = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
)

func hmacSHA256Sum(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func hkdfExpandLabel(secret, label []byte, outLen int) []byte {
	fullLen := 6 + len(label)
	info := make([]byte, 0, 4+fullLen)
	info = append(info, byte(outLen>>8), byte(outLen), byte(fullLen))
	info = append(info, []byte("tls13 ")...)
	info = append(info, label...)
	info = append(info, 0x00)

	out := make([]byte, 0, outLen)
	var t []byte
	for counter := byte(1); len(out) < outLen; counter++ {
		mac := hmac.New(sha256.New, secret)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{counter})
		t = mac.Sum(nil)
		take := outLen - len(out)
		if take > len(t) {
			take = len(t)
		}
		out = append(out, t[:take]...)
	}
	return out
}

func readQUICVarint(buf []byte, pos *int) (uint64, bool) {
	if *pos >= len(buf) {
		return 0, false
	}
	first := buf[*pos]
	length := 1 << (first >> 6)
	if *pos+length > len(buf) {
		return 0, false
	}
	val := uint64(first & 0x3f)
	for i := 1; i < length; i++ {
		val = (val << 8) | uint64(buf[*pos+i])
	}
	*pos += length
	return val, true
}

// ExtractQUICInitialSNI decrypts a QUIC v1/v2 Initial packet per RFC 9001 and extracts SNI.
func ExtractQUICInitialSNI(udpPayload []byte) (string, SNIParseStatus) {
	if len(udpPayload) < 16 {
		return "", SNINotHandshake
	}
	first := udpPayload[0]
	if (first & 0xc0) != 0xc0 {
		return "", SNINotHandshake
	}
	version := binary.BigEndian.Uint32(udpPayload[1:5])
	var salt []byte
	var isV2 bool
	switch version {
	case 0x00000001:
		salt = quicV1Salt
	case 0x6b3343cf:
		salt = quicV2Salt
		isV2 = true
	default:
		return "", SNINotHandshake
	}
	pktType := (first >> 4) & 0x03
	if (!isV2 && pktType != 0) || (isV2 && pktType != 1) {
		return "", SNINotHandshake
	}

	pos := 5
	if pos >= len(udpPayload) {
		return "", SNIMalformed
	}
	dcidLen := int(udpPayload[pos])
	pos++
	if dcidLen > 20 || pos+dcidLen >= len(udpPayload) {
		return "", SNIMalformed
	}
	dcid := udpPayload[pos : pos+dcidLen]
	pos += dcidLen

	if pos >= len(udpPayload) {
		return "", SNIMalformed
	}
	scidLen := int(udpPayload[pos])
	pos++
	if scidLen > 20 || pos+scidLen > len(udpPayload) {
		return "", SNIMalformed
	}
	pos += scidLen

	tokenLen, ok := readQUICVarint(udpPayload, &pos)
	if !ok || pos+int(tokenLen) > len(udpPayload) {
		return "", SNIMalformed
	}
	pos += int(tokenLen)

	pktLenU, ok := readQUICVarint(udpPayload, &pos)
	if !ok {
		return "", SNIMalformed
	}
	pktLen := int(pktLenU)
	if pktLen < 20 || pos+pktLen > len(udpPayload) {
		return "", SNIMalformed
	}
	pnOffset := pos
	sampleOffset := pnOffset + 4
	if sampleOffset+16 > len(udpPayload) {
		return "", SNIMalformed
	}
	sample := udpPayload[sampleOffset : sampleOffset+16]

	initialSecret := hmacSHA256Sum(salt, dcid)
	clientIn := hkdfExpandLabel(initialSecret, []byte("client in"), 32)
	lblKey, lblIV, lblHP := []byte("quic key"), []byte("quic iv"), []byte("quic hp")
	if isV2 {
		lblKey, lblIV, lblHP = []byte("quicv2 key"), []byte("quicv2 iv"), []byte("quicv2 hp")
	}
	key := hkdfExpandLabel(clientIn, lblKey, 16)
	iv := hkdfExpandLabel(clientIn, lblIV, 12)
	hpKey := hkdfExpandLabel(clientIn, lblHP, 16)

	hpBlock, err := aes.NewCipher(hpKey)
	if err != nil {
		return "", SNIMalformed
	}
	var mask [16]byte
	hpBlock.Encrypt(mask[:], sample)

	unmaskedFirst := first ^ (mask[0] & 0x0f)
	pnLen := int(unmaskedFirst&0x03) + 1
	if pnOffset+pnLen+16 > pnOffset+pktLen {
		return "", SNIMalformed
	}

	header := make([]byte, pnOffset+pnLen)
	copy(header, udpPayload[:pnOffset+pnLen])
	header[0] = unmaskedFirst
	var pnVal uint64
	for i := 0; i < pnLen; i++ {
		header[pnOffset+i] ^= mask[1+i]
		pnVal = (pnVal << 8) | uint64(header[pnOffset+i])
	}

	nonce := make([]byte, 12)
	copy(nonce, iv)
	var pnBytes [8]byte
	binary.BigEndian.PutUint64(pnBytes[:], pnVal)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= pnBytes[i]
	}

	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return "", SNIMalformed
	}
	aead, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return "", SNIMalformed
	}
	plain, err := aead.Open(nil, nonce, udpPayload[pnOffset+pnLen:pnOffset+pktLen], header)
	if err != nil {
		return "", SNIMalformed
	}

	type cryptoChunk struct {
		off  int
		data []byte
	}
	var chunks []cryptoChunk
	fpos := 0
	for fpos < len(plain) {
		ftype := plain[fpos]
		fpos++
		if ftype == 0x00 || ftype == 0x01 {
			continue
		}
		if ftype == 0x06 {
			offU, ok := readQUICVarint(plain, &fpos)
			if !ok {
				return "", SNIMalformed
			}
			lenU, ok := readQUICVarint(plain, &fpos)
			if !ok {
				return "", SNIMalformed
			}
			off, l := int(offU), int(lenU)
			if off > 8192 || fpos+l > len(plain) {
				return "", SNIMalformed
			}
			chunks = append(chunks, cryptoChunk{off: off, data: plain[fpos : fpos+l]})
			fpos += l
			continue
		}
		break
	}
	if len(chunks) == 0 {
		return "", SNIMissing
	}
	sort.Slice(chunks, func(i, j int) bool { return chunks[i].off < chunks[j].off })
	var assembled []byte
	for _, ch := range chunks {
		if ch.off == len(assembled) {
			assembled = append(assembled, ch.data...)
		} else if ch.off < len(assembled) && ch.off+len(ch.data) > len(assembled) {
			assembled = append(assembled, ch.data[len(assembled)-ch.off:]...)
		}
	}
	if len(assembled) == 0 {
		return "", SNIMalformed
	}
	return parseTLSHandshakeClientHelloSNI(assembled)
}

// EvaluateInboundSNI evaluates a raw IPv4/IPv6 packet for container inbound SNI whitelist compliance.
func EvaluateInboundSNI(rawIP []byte, isCNSrc bool) SNIDecision {
	if len(rawIP) < 20 {
		return SNIDecision{Allow: true}
	}
	version := rawIP[0] >> 4
	var srcIP netip.Addr
	var proto uint8
	var offset, totalEnd int
	switch version {
	case 4:
		ihl := int(rawIP[0]&0x0f) * 4
		if ihl < 20 || len(rawIP) < ihl {
			return SNIDecision{Allow: true}
		}
		tot := int(binary.BigEndian.Uint16(rawIP[2:4]))
		totalEnd = tot
		if totalEnd > len(rawIP) {
			totalEnd = len(rawIP)
		}
		if totalEnd < ihl {
			return SNIDecision{Allow: true}
		}
		srcIP = netip.AddrFrom4([4]byte{rawIP[12], rawIP[13], rawIP[14], rawIP[15]})
		proto = rawIP[9]
		offset = ihl
	case 6:
		if len(rawIP) < 40 {
			return SNIDecision{Allow: true}
		}
		plen := int(binary.BigEndian.Uint16(rawIP[4:6]))
		totalEnd = 40 + plen
		if totalEnd > len(rawIP) {
			totalEnd = len(rawIP)
		}
		var s [16]byte
		copy(s[:], rawIP[8:24])
		srcIP = netip.AddrFrom16(s)
		proto = rawIP[6]
		offset = 40
		for hops := 0; hops < 6 && (proto == 0 || proto == 43 || proto == 44 || proto == 60); hops++ {
			if proto == 44 {
				if offset+8 > totalEnd {
					return SNIDecision{Allow: true}
				}
				proto = rawIP[offset]
				offset += 8
			} else {
				if offset+2 > totalEnd {
					return SNIDecision{Allow: true}
				}
				next := rawIP[offset]
				hdrLen := (int(rawIP[offset+1]) + 1) * 8
				if offset+hdrLen > totalEnd {
					return SNIDecision{Allow: true}
				}
				proto = next
				offset += hdrLen
			}
		}
	default:
		return SNIDecision{Allow: true}
	}

	var dport uint16
	var payload []byte
	switch proto {
	case 6:
		if offset+20 > totalEnd {
			return SNIDecision{Allow: true}
		}
		dport = binary.BigEndian.Uint16(rawIP[offset+2 : offset+4])
		dataOff := int(rawIP[offset+12]>>4) * 4
		if dataOff < 20 || offset+dataOff > totalEnd {
			return SNIDecision{Allow: true}
		}
		payload = rawIP[offset+dataOff : totalEnd]
	case 17:
		if offset+8 > totalEnd {
			return SNIDecision{Allow: true}
		}
		dport = binary.BigEndian.Uint16(rawIP[offset+2 : offset+4])
		ulen := int(binary.BigEndian.Uint16(rawIP[offset+4 : offset+6]))
		end := totalEnd
		if ulen >= 8 && offset+ulen < end {
			end = offset + ulen
		}
		payload = rawIP[offset+8 : end]
	default:
		return SNIDecision{Allow: true}
	}
	if len(payload) == 0 {
		return SNIDecision{Allow: true, Proto: proto, DPort: dport, SrcIP: srcIP}
	}

	var sni string
	var status SNIParseStatus
	if proto == 6 {
		sni, status = ExtractTLSClientHelloSNI(payload)
	} else {
		sni, status = ExtractQUICInitialSNI(payload)
	}

	switch status {
	case SNIFound:
		if IsAllowedSNI(sni) {
			return SNIDecision{Allow: true, SNI: sni, Proto: proto, DPort: dport, SrcIP: srcIP}
		}
		return SNIDecision{Allow: false, Reason: "disallowed_sni", SNI: sni, Proto: proto, DPort: dport, SrcIP: srcIP}
	case SNIMissing, SNIMalformed:
		if isCNSrc {
			return SNIDecision{Allow: false, Reason: "missing_or_invalid_sni_cn", Proto: proto, DPort: dport, SrcIP: srcIP}
		}
		return SNIDecision{Allow: true, Proto: proto, DPort: dport, SrcIP: srcIP}
	default:
		return SNIDecision{Allow: true, Proto: proto, DPort: dport, SrcIP: srcIP}
	}
}
