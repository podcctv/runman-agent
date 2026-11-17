package hostpolicy

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"
)

func buildTestClientHelloHS(sni string) []byte {
	var ext []byte
	if sni != "" {
		nb := []byte(sni)
		entryLen := 3 + len(nb)
		listLen := entryLen
		extLen := 2 + listLen
		ext = append(ext, 0x00, 0x00)
		ext = binary.BigEndian.AppendUint16(ext, uint16(extLen))
		ext = binary.BigEndian.AppendUint16(ext, uint16(listLen))
		ext = append(ext, 0x00)
		ext = binary.BigEndian.AppendUint16(ext, uint16(len(nb)))
		ext = append(ext, nb...)
	}
	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)
	body = binary.BigEndian.AppendUint16(body, 2)
	body = append(body, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)

	hs := make([]byte, 4+len(body))
	hs[0] = 0x01
	hs[1] = byte(len(body) >> 16)
	hs[2] = byte(len(body) >> 8)
	hs[3] = byte(len(body))
	copy(hs[4:], body)
	return hs
}

func buildTestIPv4TCP(src, dst [4]byte, dport uint16, payload []byte) []byte {
	tot := 40 + len(payload)
	pkt := make([]byte, tot)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(tot))
	pkt[9] = 6
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	binary.BigEndian.PutUint16(pkt[20:22], 50000)
	binary.BigEndian.PutUint16(pkt[22:24], dport)
	pkt[32] = 0x50
	pkt[33] = 0x18
	copy(pkt[40:], payload)
	return pkt
}

func buildTestIPv4UDP(src, dst [4]byte, dport uint16, payload []byte) []byte {
	ulen := 8 + len(payload)
	tot := 20 + ulen
	pkt := make([]byte, tot)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(tot))
	pkt[9] = 17
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	binary.BigEndian.PutUint16(pkt[20:22], 40000)
	binary.BigEndian.PutUint16(pkt[22:24], dport)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(ulen))
	copy(pkt[28:], payload)
	return pkt
}

func buildTestQUICInitial(dcid, cryptoHS []byte) []byte {
	initialSecret := hmacSHA256Sum(quicV1Salt, dcid)
	clientIn := hkdfExpandLabel(initialSecret, []byte("client in"), 32)
	key := hkdfExpandLabel(clientIn, []byte("quic key"), 16)
	iv := hkdfExpandLabel(clientIn, []byte("quic iv"), 12)
	hpKey := hkdfExpandLabel(clientIn, []byte("quic hp"), 16)

	var plain []byte
	plain = append(plain, 0x06, 0x00)
	plain = binary.BigEndian.AppendUint16(plain, uint16(len(cryptoHS))|0x4000)
	plain = append(plain, cryptoHS...)
	for len(plain) < 32 {
		plain = append(plain, 0x00)
	}

	var header []byte
	header = append(header, 0xc0)
	header = binary.BigEndian.AppendUint32(header, 0x00000001)
	header = append(header, byte(len(dcid)))
	header = append(header, dcid...)
	header = append(header, 0x00, 0x00)
	pktLen := 1 + len(plain) + 16
	header = binary.BigEndian.AppendUint16(header, uint16(pktLen)|0x4000)
	pnOffset := len(header)
	header = append(header, 0x01)

	nonce := append([]byte(nil), iv...)
	nonce[11] ^= 0x01
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	sealed := aead.Seal(nil, nonce, plain, header)

	pkt := append(header, sealed...)
	hpBlock, _ := aes.NewCipher(hpKey)
	var mask [16]byte
	hpBlock.Encrypt(mask[:], pkt[pnOffset+4:pnOffset+20])
	pkt[0] ^= mask[0] & 0x0f
	pkt[pnOffset] ^= mask[1]
	return pkt
}

func TestEvaluateInboundSNITLSAndQUIC(t *testing.T) {
	allowedHS := buildTestClientHelloHS("DEB.DEBIAN.ORG.")
	tlsRec := append([]byte{0x16, 0x03, 0x01, byte(len(allowedHS) >> 8), byte(len(allowedHS))}, allowedHS...)
	if dec := EvaluateInboundSNI(buildTestIPv4TCP([4]byte{1, 2, 3, 4}, [4]byte{10, 0, 0, 2}, 443, tlsRec), true); !dec.Allow {
		t.Fatalf("expected allowed SNI to pass, got %+v", dec)
	}

	badHS := buildTestClientHelloHS("www.microsoft.com")
	badRec := append([]byte{0x16, 0x03, 0x01, byte(len(badHS) >> 8), byte(len(badHS))}, badHS...)
	dec := EvaluateInboundSNI(buildTestIPv4TCP([4]byte{8, 8, 8, 8}, [4]byte{10, 0, 0, 2}, 8443, badRec), false)
	if dec.Allow || dec.Reason != "disallowed_sni" || dec.SNI != "www.microsoft.com" {
		t.Fatalf("expected disallowed SNI block, got %+v", dec)
	}

	noSNIHS := buildTestClientHelloHS("")
	noSNIRec := append([]byte{0x16, 0x03, 0x01, byte(len(noSNIHS) >> 8), byte(len(noSNIHS))}, noSNIHS...)
	if dec := EvaluateInboundSNI(buildTestIPv4TCP([4]byte{1, 2, 3, 4}, [4]byte{10, 0, 0, 2}, 443, noSNIRec), false); !dec.Allow {
		t.Fatalf("expected non-CN missing SNI to pass, got %+v", dec)
	}
	if dec := EvaluateInboundSNI(buildTestIPv4TCP([4]byte{1, 2, 3, 4}, [4]byte{10, 0, 0, 2}, 443, noSNIRec), true); dec.Allow || dec.Reason != "missing_or_invalid_sni_cn" {
		t.Fatalf("expected CN missing SNI to block, got %+v", dec)
	}

	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	quicOK := buildTestQUICInitial(dcid, buildTestClientHelloHS("crates.io"))
	if dec := EvaluateInboundSNI(buildTestIPv4UDP([4]byte{1, 2, 3, 4}, [4]byte{10, 0, 0, 2}, 443, quicOK), true); !dec.Allow {
		t.Fatalf("expected QUIC allowed SNI to pass, got %+v", dec)
	}
	quicBad := buildTestQUICInitial(dcid, buildTestClientHelloHS("evil.example.com"))
	if dec := EvaluateInboundSNI(buildTestIPv4UDP([4]byte{8, 8, 4, 4}, [4]byte{10, 0, 0, 2}, 443, quicBad), false); dec.Allow || dec.Reason != "disallowed_sni" {
		t.Fatalf("expected QUIC disallowed SNI to block, got %+v", dec)
	}
	quicNoSNI := buildTestQUICInitial(dcid, buildTestClientHelloHS(""))
	if dec := EvaluateInboundSNI(buildTestIPv4UDP([4]byte{1, 2, 3, 4}, [4]byte{10, 0, 0, 2}, 443, quicNoSNI), true); dec.Allow || dec.Reason != "missing_or_invalid_sni_cn" {
		t.Fatalf("expected QUIC CN missing SNI to block, got %+v", dec)
	}
}
