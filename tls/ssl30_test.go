package tls

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/zmap/zcrypto/rsa"
	"github.com/zmap/zcrypto/x509"
)

// The expected values below were computed independently with Python's
// hashlib directly from the RFC 6101 formulas (Section 6.1 master secret,
// Section 6.2.2 key block, Section 5.6.9 Finished, Section 5.2.3.1 MAC).

func ssl30TestSeq(n int) []byte {
	var b [8]byte
	for i := 7; i >= 0 && n > 0; i-- {
		b[i] = byte(n)
		n >>= 8
	}
	return b[:]
}

func ssl30Range(lo, hi int) []byte {
	b := make([]byte, 0, hi-lo)
	for i := lo; i < hi; i++ {
		b = append(b, byte(i))
	}
	return b
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var (
	ssl30PreMaster    = append([]byte{0x03, 0x00}, ssl30Range(1, 47)...)
	ssl30ClientRandom = ssl30Range(0x10, 0x30)
	ssl30ServerRandom = ssl30Range(0x40, 0x60)
)

const (
	ssl30WantMaster   = "14462897aa56b0ca39fbc8c793e4883b914b1c7035e85be3659506324c7e85c98767c9eb8a7ff050608c2afddd1f78a1"
	ssl30WantKeyBlock = "6fc3b4cc340009deaf4474ad597c1d719dfea9db15165fbedbe63162b6900ab44a843b2457a8d032e29459e060d4faab69da557bcdaf81eba0b058c09abff7f61ffc1bdfef6c14285cdc7a3341894e3f957e68c5e2e7b06d9fe1f4cc4cadf501a4bf00f5063ed278"
)

func TestPRF30(t *testing.T) {
	suite := cipherSuiteByID(TLS_RSA_WITH_AES_128_CBC_SHA)
	if suite == nil {
		t.Fatal("suite not found")
	}
	ms := masterFromPreMasterSecret(VersionSSL30, suite, ssl30PreMaster, ssl30ClientRandom, ssl30ServerRandom)
	if got := hex.EncodeToString(ms); got != ssl30WantMaster {
		t.Fatalf("master secret = %s, want %s", got, ssl30WantMaster)
	}

	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV := keysFromMasterSecret(VersionSSL30, suite, ms, ssl30ClientRandom, ssl30ServerRandom, 20, 16, 16)
	var kb []byte
	for _, part := range [][]byte{clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV} {
		kb = append(kb, part...)
	}
	if got := hex.EncodeToString(kb); got != ssl30WantKeyBlock {
		t.Fatalf("key block = %s, want %s", got, ssl30WantKeyBlock)
	}
}

func TestFinishedSum30(t *testing.T) {
	suite := cipherSuiteByID(TLS_RSA_WITH_AES_128_CBC_SHA)
	ms := mustHex(t, ssl30WantMaster)
	fh := newFinishedHash(VersionSSL30, suite)
	fh.Write(bytes.Repeat([]byte("handshake messages "), 7))

	wantClient := "c5d3560f7183c7834a6c099ce58cfd444ec812dfc1425d6ae556a3c4bfcc72a86fdb206b"
	wantServer := "9e9c82e1344158233571d82186b2a64446edca483addabe52a0839d3a8ab5627fcbcd800"
	// Computing a sum must not disturb the running transcript, so each
	// one is taken twice.
	for i := 0; i < 2; i++ {
		if got := hex.EncodeToString(fh.clientSum(ms)); got != wantClient {
			t.Fatalf("client finished = %s, want %s", got, wantClient)
		}
		if got := hex.EncodeToString(fh.serverSum(ms)); got != wantServer {
			t.Fatalf("server finished = %s, want %s", got, wantServer)
		}
	}

	if _, err := fh.hashForClientCertificate(signaturePKCS1v15, 0, ms); err == nil {
		t.Fatal("hashForClientCertificate succeeded for SSLv3")
	}
}

func TestSSL30MAC(t *testing.T) {
	data := []byte("GET / HTTP/1.0\r\n\r\n")
	for _, tc := range []struct {
		macLen int
		key    []byte
		seq    int
		typ    recordType
		want   string
	}{
		{20, ssl30Range(0xa0, 0xb4), 1, recordTypeApplicationData, "733b63da97e5efc137311873c237fae233c24954"},
		{16, ssl30Range(0xc0, 0xd0), 258, recordTypeHandshake, "956c13242fcd6737e486e8706f6cb5ea"},
	} {
		m, err := newSSL30MAC(tc.macLen, tc.key)
		if err != nil {
			t.Fatal(err)
		}
		hc := &halfConn{version: VersionSSL30, mac: m}
		copy(hc.seq[:], ssl30TestSeq(tc.seq))
		// The record version (bytes 1-2) is not part of the SSLv3 MAC.
		for _, vers := range []byte{0x00, 0x01} {
			header := []byte{byte(tc.typ), 0x03, vers, byte(len(data) >> 8), byte(len(data))}
			if got := hex.EncodeToString(hc.recordMAC(header, data, nil)); got != tc.want {
				t.Errorf("MAC(len %d) = %s, want %s", tc.macLen, got, tc.want)
			}
		}
	}
	if _, err := newSSL30MAC(32, make([]byte, 32)); err == nil {
		t.Error("newSSL30MAC accepted a SHA-256 MAC length")
	}
}

func TestExtractPaddingSSL30(t *testing.T) {
	// Padding bytes are arbitrary in SSLv3; only the length byte counts.
	payload := []byte{1, 2, 3, 0xaa, 0xbb, 2}
	if n, good := extractPaddingSSL30(payload); n != 3 || good != 255 {
		t.Errorf("got (%d, %d), want (3, 255)", n, good)
	}
	if _, good := extractPaddingSSL30([]byte{1, 9}); good != 0 {
		t.Error("oversized padding accepted")
	}
}

func TestSupportedVersionsSSL30Gate(t *testing.T) {
	has := func(vs []uint16) bool {
		for _, v := range vs {
			if v == VersionSSL30 {
				return true
			}
		}
		return false
	}
	for _, tc := range []struct {
		name     string
		cfg      *Config
		isClient bool
		want     bool
	}{
		{"nil config", nil, true, false},
		{"default", &Config{}, true, false},
		{"min TLS1.0", &Config{MinVersion: VersionTLS10}, true, false},
		{"min SSL3 client", &Config{MinVersion: VersionSSL30}, true, true},
		{"min SSL3 max SSL3 client", &Config{MinVersion: VersionSSL30, MaxVersion: VersionSSL30}, true, true},
		{"min SSL3 server", &Config{MinVersion: VersionSSL30}, false, false},
	} {
		if got := has(tc.cfg.supportedVersions(tc.isClient)); got != tc.want {
			t.Errorf("%s: SSLv3 offered = %v, want %v", tc.name, got, tc.want)
		}
	}
	if v, ok := (&Config{MinVersion: VersionSSL30}).mutualVersion(false, []uint16{VersionSSL30}); ok {
		t.Errorf("server negotiated %x", v)
	}
	if v, ok := (&Config{MinVersion: VersionSSL30}).mutualVersion(true, []uint16{VersionSSL30}); !ok || v != VersionSSL30 {
		t.Errorf("client did not accept SSLv3: %x %v", v, ok)
	}
}

func TestRSAClientKeyExchangeSSL30(t *testing.T) {
	cert, err := x509.ParseCertificate(testRSACertificate)
	if err != nil {
		t.Fatal(err)
	}
	modLen := (cert.PublicKey.(*rsa.PublicKey).N.BitLen() + 7) / 8
	for _, tc := range []struct {
		version uint16
		prefix  bool
	}{{VersionSSL30, false}, {VersionTLS10, true}} {
		ka := rsaKA(tc.version)
		_, ckx, err := ka.generateClientKeyExchange(&Config{}, &clientHelloMsg{vers: VersionTLS12}, cert)
		if err != nil {
			t.Fatal(err)
		}
		wantLen := modLen
		if tc.prefix {
			wantLen += 2
		}
		if len(ckx.ciphertext) != wantLen {
			t.Errorf("version %x: ciphertext len %d, want %d", tc.version, len(ckx.ciphertext), wantLen)
		}
		if log := ckx.MakeLog(ka); log.RSAParams == nil || int(log.RSAParams.Length) != modLen {
			t.Errorf("version %x: logged EncryptedPMS length wrong", tc.version)
		}
	}
}

// TestClientHelloSupportedVersionsBelowTLS12: a client capped at SSLv3, TLS 1.0
// or TLS 1.1 sends no supported_versions (RFC 8446, Section 4.2.1 requires a
// 0x0303 legacy_version with it; OpenSSL 1.1.1 answers "bad legacy version").
func TestClientHelloSupportedVersionsBelowTLS12(t *testing.T) {
	for _, tc := range []struct {
		vers uint16
		want bool
	}{{VersionSSL30, false}, {VersionTLS10, false}, {VersionTLS11, false}, {VersionTLS12, true}} {
		m := &clientHelloMsg{vers: tc.vers, random: make([]byte, 32), cipherSuites: []uint16{TLS_RSA_WITH_AES_128_CBC_SHA},
			compressionMethods: []uint8{compressionNone}, supportedVersions: []uint16{tc.vers}}
		raw := m.marshal()
		var parsed clientHelloMsg
		if !parsed.unmarshal(raw) {
			t.Fatalf("%x: unmarshal failed", tc.vers)
		}
		if got := len(parsed.supportedVersions) > 0; got != tc.want {
			t.Errorf("%x: supported_versions sent = %v, want %v", tc.vers, got, tc.want)
		}
	}
}
