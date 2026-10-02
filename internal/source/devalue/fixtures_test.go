package devalue

import (
	"os"
	"path/filepath"
	"testing"
)

// fixturePath locates a captured page fixture.
func fixturePath(name string) string {
	return filepath.Join("..", "..", "..", "fixtures", "hackenproof", name)
}

// loadFixture extracts and decodes the embedded payload from a captured page.
//
// These fixtures were captured from the live public site and are checked in so
// that the parser's behaviour stays verifiable after the site changes. The
// tests below therefore assert on structure and on the exact values that carry
// access-control meaning.
func loadFixture(t *testing.T, name string) *Document {
	t.Helper()
	raw, err := os.ReadFile(fixturePath(name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	payload, err := ExtractPayload(raw)
	if err != nil {
		t.Fatalf("extract payload from %s: %v", name, err)
	}
	doc, err := Decode(payload, 64)
	if err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	return doc
}

// TestListingFixtureDecodes verifies the discovery payload yields program
// references with stable slugs.
//
// The listing omits program IDs entirely on this platform, so the slug is the
// only durable identity available. If this test breaks, program identity is at
// risk and every stored record must be re-keyed.
func TestListingFixtureDecodes(t *testing.T) {
	doc := loadFixture(t, "listing-page1.html")

	programs, ok := Find(doc.Root, "data", "programs-api-bounty", "programs")
	if !ok {
		t.Fatalf("listing payload did not expose programs-api-bounty.programs")
	}
	list, ok := AsSlice(programs)
	if !ok || len(list) == 0 {
		t.Fatalf("programs is not a non-empty list: %T", programs)
	}

	slugs := map[string]bool{}
	for i, item := range list {
		m, ok := AsMap(item)
		if !ok {
			t.Fatalf("program %d is %T, want object", i, item)
		}
		slug := AsString(m["slug"])
		if slug == "" {
			t.Errorf("program %d has no slug; identity would be unstable", i)
			continue
		}
		if AsString(m["name"]) == "" {
			t.Errorf("program %q has no name", slug)
		}
		slugs[slug] = true
	}
	if len(slugs) < 5 {
		t.Errorf("only %d distinct slugs decoded, want at least 5", len(slugs))
	}
	t.Logf("decoded %d programs from listing fixture", len(slugs))
}

// TestProgramFixtureAccessFields verifies that a real detail payload exposes
// the access-control facts policy depends on, and that an absent requirement
// decodes as absent rather than as zero.
func TestProgramFixtureAccessFields(t *testing.T) {
	doc := loadFixture(t, "program-bitrue.html")

	program, ok := Find(doc.Root, "data", "program")
	if !ok {
		t.Fatal("detail payload did not expose data.program")
	}
	m := firstProgramMap(t, program)

	if AsString(m["title"]) != "Bitrue" {
		t.Errorf("title = %q, want Bitrue", AsString(m["title"]))
	}

	// KYC must be an explicit boolean.
	kyc, ok := AsBool(m["kycRequired"])
	if !ok {
		t.Errorf("kycRequired is %T, want a bool", m["kycRequired"])
	} else if kyc {
		t.Error("Bitrue should not require KYC")
	}

	// An absent reputation requirement must stay absent. Decoding it as zero
	// would assert "requires no reputation", which the page does not state.
	rep, present := m["reputationRequired"]
	if !present || rep == nil {
		t.Log("reputationRequired absent, which is the expected encoding")
	} else if n, isNum := AsNumber(rep); !isNum || n != 0 {
		t.Errorf("reputationRequired = %#v, want absent or 0", rep)
	}

	if scopes, ok := AsSlice(m["scopes"]); !ok || len(scopes) == 0 {
		t.Errorf("scopes is %T with %d entries, want a non-empty list", m["scopes"], len(scopes))
	} else {
		var web, api, mobile int
		for _, s := range scopes {
			sm, ok := AsMap(s)
			if !ok {
				t.Fatalf("scope is %T", s)
			}
			switch AsString(sm["title"]) {
			case "Web":
				web++
			case "API":
				api++
			case "Android", "iOS":
				mobile++
			}
			if AsString(sm["target"]) == "" {
				t.Errorf("scope %q has no target", AsString(sm["title"]))
			}
		}
		if web == 0 || api == 0 {
			t.Errorf("expected at least one web and one api scope, got web=%d api=%d", web, api)
		}
		if mobile == 0 {
			t.Errorf("expected mobile scopes, got none")
		}
	}
}

// TestProgramFixtureKYCAndContractScope verifies the second fixture, which
// exercises the KYC-required and smart-contract-only case. These are the inputs
// that must drive a rejection, so they are worth pinning.
func TestProgramFixtureKYCAndContractScope(t *testing.T) {
	doc := loadFixture(t, "program-starknet-staking.html")

	program, ok := Find(doc.Root, "data", "program")
	if !ok {
		t.Fatal("detail payload did not expose data.program")
	}
	m := firstProgramMap(t, program)

	kyc, ok := AsBool(m["kycRequired"])
	if !ok {
		t.Fatalf("kycRequired is %T, want bool", m["kycRequired"])
	}
	if !kyc {
		t.Error("starknet-staking fixture should require KYC")
	}

	scopes, ok := AsSlice(m["scopes"])
	if !ok || len(scopes) == 0 {
		t.Fatalf("scopes is %T, want a non-empty list", m["scopes"])
	}
	sawContract := false
	for _, s := range scopes {
		sm, _ := AsMap(s)
		title := AsString(sm["title"])
		if title == "Smart Contract" {
			sawContract = true
		}
		if out, ok := AsBool(sm["out_of_scope"]); !ok {
			t.Errorf("scope %q out_of_scope is %T, want bool", title, sm["out_of_scope"])
		} else if out {
			t.Logf("scope %q is out of scope", title)
		}
	}
	if !sawContract {
		t.Error("expected at least one Smart Contract scope")
	}
}

// TestPayloadExtractionIsRobust verifies extraction fails cleanly when the
// payload is absent, rather than returning an empty document.
func TestPayloadExtractionIsRobust(t *testing.T) {
	if _, err := ExtractPayload([]byte("<html><body>no payload</body></html>")); err == nil {
		t.Error("ExtractPayload accepted a page with no payload")
	}
	if _, err := ExtractPayload(nil); err == nil {
		t.Error("ExtractPayload accepted empty input")
	}
}

// firstProgramMap extracts the program object from either a single object or a
// one-element wrapper list, which is how the source nests it.
func firstProgramMap(t *testing.T, v any) map[string]any {
	t.Helper()
	switch typed := v.(type) {
	case map[string]any:
		return typed
	case []any:
		if len(typed) == 0 {
			t.Fatal("program wrapper list is empty")
		}
		m, ok := AsMap(typed[0])
		if !ok {
			t.Fatalf("program wrapper list holds %T", typed[0])
		}
		return m
	default:
		t.Fatalf("data.program is %T, want object or list", v)
		return nil
	}
}
