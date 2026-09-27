// Copyright 2026 The Update Framework Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package sigstoreverify

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	sigstoreroot "github.com/sigstore/sigstore-go/pkg/root"
	sigstoreverify "github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// This is a pinned snapshot of Sigstore Public Good trusted material.
// Keeping it local preserves offline TUF verification. It must be updated
// deliberately when Sigstore rotates trust material.
//
//go:embed trusted-root-public-good.json
var trustedRootJSON []byte

var (
	trustedRootOnce sync.Once
	trustedRoot     *sigstoreroot.TrustedRoot
	trustedRootErr  error
)

func init() {
	metadata.RegisterSignatureVerifier(metadata.KeyTypeSigstoreOIDC, verify)
}

func loadTrustedRoot() (*sigstoreroot.TrustedRoot, error) {
	trustedRootOnce.Do(func() {
		trustedRoot, trustedRootErr = sigstoreroot.NewTrustedRootFromJSON(trustedRootJSON)
	})
	return trustedRoot, trustedRootErr
}

func identity(key *metadata.Key) (string, string, error) {
	if key.Type != metadata.KeyTypeSigstoreOIDC || key.Scheme != metadata.KeySchemeSigstoreFulcio {
		return "", "", errors.New("unsupported Sigstore TUF key")
	}
	id, ok := key.Value.UnrecognizedFields["identity"].(string)
	if !ok || id == "" {
		return "", "", errors.New("Sigstore TUF key has no identity")
	}
	issuer, ok := key.Value.UnrecognizedFields["issuer"].(string)
	if !ok || issuer == "" {
		return "", "", errors.New("Sigstore TUF key has no issuer")
	}
	return id, issuer, nil
}

func verify(key *metadata.Key, signature metadata.Signature, payload []byte) (string, error) {
	id, issuer, err := identity(key)
	if err != nil {
		return "", err
	}
	bundleValue, ok := signature.UnrecognizedFields["bundle"]
	if !ok {
		return "", errors.New("Sigstore TUF signature has no bundle")
	}
	bundleJSON, err := json.Marshal(bundleValue)
	if err != nil {
		return "", fmt.Errorf("marshal Sigstore bundle: %w", err)
	}

	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return "", fmt.Errorf("parse Sigstore bundle: %w", err)
	}
	signatureContent, err := b.SignatureContent()
	if err != nil {
		return "", fmt.Errorf("read Sigstore bundle signature: %w", err)
	}
	messageSignature := signatureContent.MessageSignatureContent()
	if messageSignature == nil || !bytes.Equal(messageSignature.Signature(), signature.Signature) {
		return "", errors.New("Sigstore bundle signature does not match TUF sig field")
	}

	root, err := loadTrustedRoot()
	if err != nil {
		return "", fmt.Errorf("load Sigstore trusted root: %w", err)
	}
	verifier, err := sigstoreverify.NewVerifier(
		root,
		sigstoreverify.WithSignedCertificateTimestamps(1),
		sigstoreverify.WithTransparencyLog(1),
		sigstoreverify.WithIntegratedTimestamps(1),
	)
	if err != nil {
		return "", fmt.Errorf("create Sigstore verifier: %w", err)
	}
	certIdentity, err := sigstoreverify.NewShortCertificateIdentity(issuer, "", id, "")
	if err != nil {
		return "", fmt.Errorf("create Sigstore identity policy: %w", err)
	}
	_, err = verifier.Verify(
		&b,
		sigstoreverify.NewPolicy(
			sigstoreverify.WithArtifact(bytes.NewReader(payload)),
			sigstoreverify.WithCertificateIdentity(certIdentity),
		),
	)
	if err != nil {
		return "", fmt.Errorf("verify Sigstore TUF signature: %w", err)
	}

	sum := sha256.Sum256([]byte(issuer + "\x00" + id))
	return "sigstore:" + hex.EncodeToString(sum[:]), nil
}
