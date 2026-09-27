package sigstoreverify

import (
	"os"
	"testing"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func productionRoot(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/bnh-production-root.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func parseProductionRoot(t *testing.T, raw []byte) *metadata.Metadata[metadata.RootType] {
	t.Helper()
	root, err := metadata.Root().FromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestBNHProductionSigstoreRootVerifiesOffline(t *testing.T) {
	raw := productionRoot(t)
	root := parseProductionRoot(t, raw)
	keyID := root.Signed.Roles[metadata.ROOT].KeyIDs[0]
	payload, err := cjson.EncodeCanonical(root.Signed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = verify(root.Signed.Keys[keyID], root.Signatures[0], payload); err != nil {
		t.Fatalf("direct Sigstore verification failed: %v", err)
	}
	if err := root.VerifyDelegate(metadata.ROOT, root); err != nil {
		t.Fatalf("production Sigstore root did not verify: %v", err)
	}
}

func TestBNHProductionSigstoreRootRejectsWrongIdentity(t *testing.T) {
	raw := productionRoot(t)
	delegator := parseProductionRoot(t, raw)
	delegated := parseProductionRoot(t, raw)

	keyID := delegator.Signed.Roles[metadata.ROOT].KeyIDs[0]
	key := delegator.Signed.Keys[keyID]
	key.Value.UnrecognizedFields["identity"] = "attacker@example.invalid"

	if err := delegator.VerifyDelegate(metadata.ROOT, delegated); err == nil {
		t.Fatal("production Sigstore root verified for the wrong OIDC identity")
	}
}

func TestBNHProductionSigstoreRootRejectsMissingBundle(t *testing.T) {
	raw := productionRoot(t)
	delegator := parseProductionRoot(t, raw)
	delegated := parseProductionRoot(t, raw)

	delete(delegated.Signatures[0].UnrecognizedFields, "bundle")
	if err := delegator.VerifyDelegate(metadata.ROOT, delegated); err == nil {
		t.Fatal("production Sigstore root verified without its Sigstore bundle")
	}
}

func TestBNHProductionSigstoreRootRejectsSigBundleMismatch(t *testing.T) {
	raw := productionRoot(t)
	delegator := parseProductionRoot(t, raw)
	delegated := parseProductionRoot(t, raw)

	delegated.Signatures[0].Signature[0] ^= 0xff
	if err := delegator.VerifyDelegate(metadata.ROOT, delegated); err == nil {
		t.Fatal("production Sigstore root verified with a sig field that does not match the bundle")
	}
}
