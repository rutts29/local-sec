package lsec

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLLMReviewCacheStoreLoadRoundTrip(t *testing.T) {
	root := t.TempDir()
	cache := NewLLMReviewCache(root)
	key := testLLMCacheKey(strings.Repeat("a", 64))
	review := testLLMCacheReview(key.EvidenceSHA256)

	if err := cache.Store(key, review); err != nil {
		t.Fatalf("store review: %v", err)
	}
	got, ok, err := cache.Load(key)
	if err != nil {
		t.Fatalf("load review: %v", err)
	}
	if !ok {
		t.Fatal("load review miss, want hit")
	}
	if !reflect.DeepEqual(got, review) {
		t.Fatalf("review = %#v, want %#v", got, review)
	}
}

func TestLLMReviewCacheMiss(t *testing.T) {
	cache := NewLLMReviewCache(t.TempDir())

	review, ok, err := cache.Load(testLLMCacheKey(strings.Repeat("a", 64)))
	if err != nil {
		t.Fatalf("load missing review: %v", err)
	}
	if ok {
		t.Fatalf("load missing review hit with %#v", review)
	}
}

func TestLLMReviewCacheRejectsInvalidAndMismatchedKeys(t *testing.T) {
	cache := NewLLMReviewCache(t.TempDir())
	validKey := testLLMCacheKey(strings.Repeat("a", 64))
	validReview := testLLMCacheReview(validKey.EvidenceSHA256)

	tests := []struct {
		name        string
		key         LLMCacheKey
		review      LLMReview
		loadInvalid bool
	}{
		{name: "empty provider", key: LLMCacheKey{Model: "llama3", Schema: LLMReviewSchema, EvidenceSHA256: validKey.EvidenceSHA256}, review: validReview, loadInvalid: true},
		{name: "empty model", key: LLMCacheKey{Provider: "ollama", Schema: LLMReviewSchema, EvidenceSHA256: validKey.EvidenceSHA256}, review: validReview, loadInvalid: true},
		{name: "empty schema", key: LLMCacheKey{Provider: "ollama", Model: "llama3", EvidenceSHA256: validKey.EvidenceSHA256}, review: validReview, loadInvalid: true},
		{name: "invalid schema", key: LLMCacheKey{Provider: "ollama", Model: "llama3", Schema: LLMReviewSchema + "/../../escape", EvidenceSHA256: validKey.EvidenceSHA256}, review: validReview, loadInvalid: true},
		{name: "empty hash", key: LLMCacheKey{Provider: "ollama", Model: "llama3", Schema: LLMReviewSchema}, review: validReview, loadInvalid: true},
		{name: "bad hash", key: LLMCacheKey{Provider: "ollama", Model: "llama3", Schema: LLMReviewSchema, EvidenceSHA256: "not-a-hash"}, review: validReview, loadInvalid: true},
		{name: "mismatched review hash", key: validKey, review: testLLMCacheReview(strings.Repeat("b", 64))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := cache.Store(tt.key, tt.review); err == nil {
				t.Fatal("store accepted invalid key or mismatched review")
			}
			if tt.loadInvalid {
				if _, _, err := cache.Load(tt.key); err == nil {
					t.Fatal("load accepted invalid key")
				}
				return
			}
			if err := os.MkdirAll(cache.root, 0o700); err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(tt.review)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(cache.root, llmReviewCacheFileName(tt.key)), body, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := cache.Load(tt.key); err == nil {
				t.Fatal("load accepted invalid key")
			}
		})
	}
}

func TestLLMReviewCachePathTraversalStringsDoNotAffectOutputPath(t *testing.T) {
	root := t.TempDir()
	cache := NewLLMReviewCache(root)
	key := LLMCacheKey{
		Provider:       "../ollama",
		Model:          "..//model",
		Schema:         LLMReviewSchema,
		EvidenceSHA256: strings.Repeat("a", 64),
	}
	review := testLLMCacheReview(key.EvidenceSHA256)

	if err := cache.Store(key, review); err != nil {
		t.Fatalf("store traversal key: %v", err)
	}
	got, ok, err := cache.Load(key)
	if err != nil {
		t.Fatalf("load traversal key: %v", err)
	}
	if !ok || !reflect.DeepEqual(got, review) {
		t.Fatalf("review = %#v, ok = %v; want %#v hit", got, ok, review)
	}

	var files []string
	if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			files = append(files, path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("cache files = %v, want one file under cache root", files)
	}
	if filepath.Dir(files[0]) != root {
		t.Fatalf("cache file path = %q, want direct child of %q", files[0], root)
	}
}

func TestLLMReviewCacheRejectsUnknownFieldsOnLoad(t *testing.T) {
	root := t.TempDir()
	cache := NewLLMReviewCache(root)
	key := testLLMCacheKey(strings.Repeat("a", 64))
	body := `{
		"schema": "lsec.llm_review",
		"version": 1,
		"evidence_sha256": "` + key.EvidenceSHA256 + `",
		"verdict": "prompt",
		"confidence": "medium",
		"reasons": ["credential exfiltration signal"],
		"signals": ["network canary"],
		"raw_response": "must not be cached"
	}`

	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, llmReviewCacheFileName(key)), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cache.Load(key); err == nil {
		t.Fatal("load accepted cached review with unknown field")
	}
}

func TestLLMReviewCacheRejectsTrailingContentOnLoad(t *testing.T) {
	root := t.TempDir()
	cache := NewLLMReviewCache(root)
	key := testLLMCacheKey(strings.Repeat("a", 64))
	body, err := json.Marshal(testLLMCacheReview(key.EvidenceSHA256))
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, []byte("\n{\"raw_response\":\"must not be cached\"}")...)

	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, llmReviewCacheFileName(key)), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cache.Load(key); err == nil {
		t.Fatal("load accepted cached review with trailing content")
	}
}

func TestLLMReviewCacheStoresNoPromptOrRawResponseFields(t *testing.T) {
	root := t.TempDir()
	cache := NewLLMReviewCache(root)
	key := testLLMCacheKey(strings.Repeat("a", 64))

	if err := cache.Store(key, testLLMCacheReview(key.EvidenceSHA256)); err != nil {
		t.Fatalf("store review: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(root, llmReviewCacheFileName(key)))
	if err != nil {
		t.Fatal(err)
	}
	var stored map[string]json.RawMessage
	if err := json.Unmarshal(body, &stored); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{
		"schema":          true,
		"version":         true,
		"evidence_sha256": true,
		"verdict":         true,
		"confidence":      true,
		"reasons":         true,
		"signals":         true,
	}
	for field := range stored {
		if !allowed[field] {
			t.Fatalf("cached review contains non-review field %q: %s", field, body)
		}
	}
	for _, forbidden := range []string{"prompt", "raw_response", "response"} {
		if _, ok := stored[forbidden]; ok {
			t.Fatalf("cached review contains forbidden field %q: %s", forbidden, body)
		}
	}
}

func TestLLMReviewCacheLoadSanitizesReviewText(t *testing.T) {
	root := t.TempDir()
	cache := NewLLMReviewCache(root)
	key := testLLMCacheKey(strings.Repeat("a", 64))
	review := testLLMCacheReview(key.EvidenceSHA256)
	review.Reasons = []string{"found /Users/alice/.npmrc ghp_abcdefghijklmnopqrstuvwxyz123456"}
	review.Signals = []string{"sent sk-abcdefghijklmnopqrstuvwxyz lsec-canary-openai-api-key"}
	body, err := json.Marshal(review)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, llmReviewCacheFileName(key)), body, 0o600); err != nil {
		t.Fatal(err)
	}

	got, ok, err := cache.Load(key)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("cache miss, want hit")
	}
	combined := strings.Join(append(got.Reasons, got.Signals...), "\n")
	for _, forbidden := range []string{"/Users/alice", "ghp_", "sk-", "lsec-canary-"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("loaded review contains %q: %#v", forbidden, got)
		}
	}
	if !strings.Contains(combined, "[redacted-secret]") || !strings.Contains(combined, "npmrc") {
		t.Fatalf("loaded review = %#v, want sanitized review text", got)
	}
}

func testLLMCacheKey(hash string) LLMCacheKey {
	return LLMCacheKey{
		Provider:       "ollama",
		Model:          "llama3",
		Schema:         LLMReviewSchema,
		EvidenceSHA256: hash,
	}
}

func testLLMCacheReview(hash string) LLMReview {
	return LLMReview{
		Schema:         LLMReviewSchema,
		Version:        LLMReviewSchemaVersion,
		EvidenceSHA256: hash,
		Verdict:        VerdictPrompt,
		Confidence:     "medium",
		Reasons:        []string{"credential exfiltration signal"},
		Signals:        []string{"network canary"},
	}
}
