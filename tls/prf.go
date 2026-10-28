// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
)

// Split a premaster secret in two as specified in RFC 4346, Section 5.
func splitPreMasterSecret(secret []byte) (s1, s2 []byte) {
	s1 = secret[0 : (len(secret)+1)/2]
	s2 = secret[len(secret)/2:]
	return
}

// pHash implements the P_hash function, as defined in RFC 4346, Section 5.
func pHash(result, secret, seed []byte, hash func() hash.Hash) {
	h := hmac.New(hash, secret)
	h.Write(seed)
	a := h.Sum(nil)

	j := 0
	for j < len(result) {
		h.Reset()
		h.Write(a)
		h.Write(seed)
		b := h.Sum(nil)
		copy(result[j:], b)
		j += len(b)

		h.Reset()
		h.Write(a)
		a = h.Sum(nil)
	}
}

// prf10 implements the TLS 1.0 pseudo-random function, as defined in RFC 2246, Section 5.
func prf10(result, secret, label, seed []byte) {
	hashSHA1 := sha1.New
	hashMD5 := md5.New

	labelAndSeed := make([]byte, len(label)+len(seed))
	copy(labelAndSeed, label)
	copy(labelAndSeed[len(label):], seed)

	s1, s2 := splitPreMasterSecret(secret)
	pHash(result, s1, labelAndSeed, hashMD5)
	result2 := make([]byte, len(result))
	pHash(result2, s2, labelAndSeed, hashSHA1)

	for i, b := range result2 {
		result[i] ^= b
	}
}

// prf12 implements the TLS 1.2 pseudo-random function, as defined in RFC 5246, Section 5.
func prf12(hashFunc func() hash.Hash) func(result, secret, label, seed []byte) {
	return func(result, secret, label, seed []byte) {
		labelAndSeed := make([]byte, len(label)+len(seed))
		copy(labelAndSeed, label)
		copy(labelAndSeed[len(label):], seed)

		pHash(result, secret, labelAndSeed, hashFunc)
	}
}

// prf30 implements the SSL 3.0 pseudo-random function used for the master
// secret (RFC 6101, Section 6.1) and the key block (RFC 6101, Section 6.2.2):
//
//	MD5(secret + SHA('A' + secret + seed)) +
//	MD5(secret + SHA('BB' + secret + seed)) + ...
//
// The label is not part of the SSL 3.0 construction and is ignored. Ported
// from Go 1.13 crypto/tls.
func prf30(result, secret, label, seed []byte) {
	hashSHA1 := sha1.New()
	hashMD5 := md5.New()

	done := 0
	i := 0
	// RFC 5246, Section 6.3 says that the largest PRF output needed is 128
	// bytes. Each iteration gives 16 bytes, so 10 iterations suffice; the
	// salt is capped at 26 letters ('A'..'Z') regardless.
	var b [26]byte
	for done < len(result) {
		if i >= len(b) {
			panic("tls: prf30 output too long")
		}
		for j := 0; j <= i; j++ {
			b[j] = 'A' + byte(i)
		}

		hashSHA1.Reset()
		hashSHA1.Write(b[:i+1])
		hashSHA1.Write(secret)
		hashSHA1.Write(seed)
		digest := hashSHA1.Sum(nil)

		hashMD5.Reset()
		hashMD5.Write(secret)
		hashMD5.Write(digest)

		done += copy(result[done:], hashMD5.Sum(nil))
		i++
	}
}

const (
	masterSecretLength   = 48 // Length of a master secret in TLS 1.1.
	finishedVerifyLength = 12 // Length of verify_data in a Finished message.
)

var masterSecretLabel = []byte("master secret")
var keyExpansionLabel = []byte("key expansion")
var clientFinishedLabel = []byte("client finished")
var serverFinishedLabel = []byte("server finished")

func prfAndHashForVersion(version uint16, suite *cipherSuite) (func(result, secret, label, seed []byte), crypto.Hash) {
	switch version {
	case VersionSSL30:
		return prf30, crypto.Hash(0)
	case VersionTLS10, VersionTLS11:
		return prf10, crypto.Hash(0)
	case VersionTLS12:
		if suite.flags&suiteSHA384 != 0 {
			return prf12(sha512.New384), crypto.SHA384
		}
		return prf12(sha256.New), crypto.SHA256
	default:
		panic("unknown version")
	}
}

func prfForVersion(version uint16, suite *cipherSuite) func(result, secret, label, seed []byte) {
	prf, _ := prfAndHashForVersion(version, suite)
	return prf
}

// masterFromPreMasterSecret generates the master secret from the pre-master
// secret. See RFC 5246, Section 8.1.
func masterFromPreMasterSecret(version uint16, suite *cipherSuite, preMasterSecret, clientRandom, serverRandom []byte) []byte {
	seed := make([]byte, 0, len(clientRandom)+len(serverRandom))
	seed = append(seed, clientRandom...)
	seed = append(seed, serverRandom...)

	masterSecret := make([]byte, masterSecretLength)
	prfForVersion(version, suite)(masterSecret, preMasterSecret, masterSecretLabel, seed)
	return masterSecret
}

// keysFromMasterSecret generates the connection keys from the master
// secret, given the lengths of the MAC key, cipher key and IV, as defined in
// RFC 2246, Section 6.3.
func keysFromMasterSecret(version uint16, suite *cipherSuite, masterSecret, clientRandom, serverRandom []byte, macLen, keyLen, ivLen int) (clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV []byte) {
	seed := make([]byte, 0, len(serverRandom)+len(clientRandom))
	seed = append(seed, serverRandom...)
	seed = append(seed, clientRandom...)

	n := 2*macLen + 2*keyLen + 2*ivLen
	keyMaterial := make([]byte, n)
	prfForVersion(version, suite)(keyMaterial, masterSecret, keyExpansionLabel, seed)
	clientMAC = keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]
	serverMAC = keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]
	clientKey = keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]
	serverKey = keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]
	clientIV = keyMaterial[:ivLen]
	keyMaterial = keyMaterial[ivLen:]
	serverIV = keyMaterial[:ivLen]
	return
}

func newFinishedHash(version uint16, cipherSuite *cipherSuite) finishedHash {
	var buffer []byte
	if version >= VersionTLS12 {
		buffer = []byte{}
	}

	prf, hash := prfAndHashForVersion(version, cipherSuite)
	if hash != 0 {
		return finishedHash{hash.New(), hash.New(), nil, nil, buffer, version, prf}
	}

	return finishedHash{sha1.New(), sha1.New(), md5.New(), md5.New(), buffer, version, prf}
}

// A finishedHash calculates the hash of a set of handshake messages suitable
// for including in a Finished message.
type finishedHash struct {
	client hash.Hash
	server hash.Hash

	// Prior to TLS 1.2, an additional MD5 hash is required.
	clientMD5 hash.Hash
	serverMD5 hash.Hash

	// In TLS 1.2, a full buffer is sadly required.
	buffer []byte

	version uint16
	prf     func(result, secret, label, seed []byte)
}

func (h *finishedHash) Write(msg []byte) (n int, err error) {
	h.client.Write(msg)
	h.server.Write(msg)

	if h.version < VersionTLS12 {
		h.clientMD5.Write(msg)
		h.serverMD5.Write(msg)
	}

	if h.buffer != nil {
		h.buffer = append(h.buffer, msg...)
	}

	return len(msg), nil
}

func (h finishedHash) Sum() []byte {
	if h.version >= VersionTLS12 {
		return h.client.Sum(nil)
	}

	out := make([]byte, 0, md5.Size+sha1.Size)
	out = h.clientMD5.Sum(out)
	return h.client.Sum(out)
}

// finishedSum30 calculates the contents of the verify_data member of an SSLv3
// Finished message (RFC 6101, Section 5.6.9) given the MD5 and SHA-1 hashes
// of the handshake messages so far:
//
//	md5_hash = MD5(master_secret + pad2 + MD5(handshake_messages + Sender + master_secret + pad1))
//	sha_hash = SHA(master_secret + pad2 + SHA(handshake_messages + Sender + master_secret + pad1))
//
// pad1/pad2 are 48 bytes for MD5 and 40 bytes for SHA. The result is 36 bytes.
// md5 and sha1 are modified. Ported from Go 1.13 crypto/tls.
func finishedSum30(md5, sha1 hash.Hash, masterSecret []byte, magic []byte) []byte {
	md5.Write(magic)
	md5.Write(masterSecret)
	md5.Write(ssl30Pad1[:])
	md5Digest := md5.Sum(nil)

	md5.Reset()
	md5.Write(masterSecret)
	md5.Write(ssl30Pad2[:])
	md5.Write(md5Digest)
	md5Digest = md5.Sum(nil)

	sha1.Write(magic)
	sha1.Write(masterSecret)
	sha1.Write(ssl30Pad1[:40])
	sha1Digest := sha1.Sum(nil)

	sha1.Reset()
	sha1.Write(masterSecret)
	sha1.Write(ssl30Pad2[:40])
	sha1.Write(sha1Digest)
	sha1Digest = sha1.Sum(nil)

	ret := make([]byte, len(md5Digest)+len(sha1Digest))
	copy(ret, md5Digest)
	copy(ret[len(md5Digest):], sha1Digest)
	return ret
}

// Sender values of RFC 6101, Section 5.6.9.
var ssl3ClientFinishedMagic = [4]byte{0x43, 0x4c, 0x4e, 0x54} // "CLNT"
var ssl3ServerFinishedMagic = [4]byte{0x53, 0x52, 0x56, 0x52} // "SRVR"

// cloneTranscript returns an independent copy of a running MD5 or SHA-1
// transcript hash, so that finishedSum30, which writes into its inputs,
// leaves the transcript intact.
func cloneTranscript(in hash.Hash, h crypto.Hash) hash.Hash {
	out := cloneHash(in, h)
	if out == nil {
		panic("tls: failed to clone the handshake transcript hash")
	}
	return out
}

// clientSum returns the contents of the verify_data member of a client's
// Finished message.
func (h finishedHash) clientSum(masterSecret []byte) []byte {
	if h.version == VersionSSL30 {
		return finishedSum30(cloneTranscript(h.clientMD5, crypto.MD5), cloneTranscript(h.client, crypto.SHA1), masterSecret, ssl3ClientFinishedMagic[:])
	}
	out := make([]byte, finishedVerifyLength)
	h.prf(out, masterSecret, clientFinishedLabel, h.Sum())
	return out
}

// serverSum returns the contents of the verify_data member of a server's
// Finished message.
func (h finishedHash) serverSum(masterSecret []byte) []byte {
	if h.version == VersionSSL30 {
		return finishedSum30(cloneTranscript(h.serverMD5, crypto.MD5), cloneTranscript(h.server, crypto.SHA1), masterSecret, ssl3ServerFinishedMagic[:])
	}
	out := make([]byte, finishedVerifyLength)
	h.prf(out, masterSecret, serverFinishedLabel, h.Sum())
	return out
}

// hashForClientCertificate returns the handshake messages so far, pre-hashed if
// necessary, suitable for signing by a TLS client certificate.
func (h finishedHash) hashForClientCertificate(sigType uint8, hashAlg crypto.Hash, masterSecret []byte) ([]byte, error) {
	if h.version == VersionSSL30 {
		// The SSLv3 CertificateVerify construction (RFC 6101, Section
		// 5.6.8) is not implemented: SSLv3 is only supported as a client
		// for scanning, without client certificates.
		return nil, errors.New("tls: client certificates are not supported in SSLv3")
	}
	if (h.version >= VersionTLS12 || sigType == signatureEd25519) && h.buffer == nil {
		panic("tls: handshake hash for a client certificate requested after discarding the handshake buffer")
	}

	if sigType == signatureEd25519 {
		return h.buffer, nil
	}

	if h.version >= VersionTLS12 {
		hash := hashAlg.New()
		hash.Write(h.buffer)
		return hash.Sum(nil), nil
	}

	if sigType == signatureECDSA {
		return h.server.Sum(nil), nil
	}

	return h.Sum(), nil
}

// discardHandshakeBuffer is called when there is no more need to
// buffer the entirety of the handshake messages.
func (h *finishedHash) discardHandshakeBuffer() {
	h.buffer = nil
}

// noExportedKeyingMaterial is used as a value of
// ConnectionState.ekm when renegotiation is enabled and thus
// we wish to fail all key-material export requests.
func noExportedKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	return nil, errors.New("crypto/tls: ExportKeyingMaterial is unavailable when renegotiation is enabled")
}

// ekmFromMasterSecret generates exported keying material as defined in RFC 5705.
func ekmFromMasterSecret(version uint16, suite *cipherSuite, masterSecret, clientRandom, serverRandom []byte) func(string, []byte, int) ([]byte, error) {
	if version == VersionSSL30 {
		// RFC 5705 exporters are not defined for SSLv3.
		return noExportedKeyingMaterial
	}
	return func(label string, context []byte, length int) ([]byte, error) {
		switch label {
		case "client finished", "server finished", "master secret", "key expansion":
			// These values are reserved and may not be used.
			return nil, fmt.Errorf("crypto/tls: reserved ExportKeyingMaterial label: %s", label)
		}

		seedLen := len(serverRandom) + len(clientRandom)
		if context != nil {
			seedLen += 2 + len(context)
		}
		seed := make([]byte, 0, seedLen)

		seed = append(seed, clientRandom...)
		seed = append(seed, serverRandom...)

		if context != nil {
			if len(context) >= 1<<16 {
				return nil, fmt.Errorf("crypto/tls: ExportKeyingMaterial context too long")
			}
			seed = append(seed, byte(len(context)>>8), byte(len(context)))
			seed = append(seed, context...)
		}

		keyMaterial := make([]byte, length)
		prfForVersion(version, suite)(keyMaterial, masterSecret, []byte(label), seed)
		return keyMaterial, nil
	}
}
