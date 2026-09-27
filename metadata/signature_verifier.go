// Copyright 2026 The Update Framework Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package metadata

import "sync"

// SignatureVerifier verifies one metadata signature for a non-core TUF key type.
// It returns a stable signer fingerprint used for threshold de-duplication.
type SignatureVerifier func(key *Key, signature Signature, payload []byte) (string, error)

var signatureVerifiers sync.Map

// RegisterSignatureVerifier registers a verifier for an extension key type.
// Registration is intended for package initialization and panics on duplicates.
func RegisterSignatureVerifier(keyType string, verifier SignatureVerifier) {
	if keyType == "" || verifier == nil {
		panic("metadata: invalid signature verifier registration")
	}
	if _, loaded := signatureVerifiers.LoadOrStore(keyType, verifier); loaded {
		panic("metadata: duplicate signature verifier registration for " + keyType)
	}
}

func signatureVerifierFor(keyType string) (SignatureVerifier, bool) {
	value, ok := signatureVerifiers.Load(keyType)
	if !ok {
		return nil, false
	}
	return value.(SignatureVerifier), true
}
