package lsec

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type LLMCacheKey struct {
	Provider       string
	Model          string
	Schema         string
	EvidenceSHA256 string
}

type LLMReviewCache struct {
	root string
}

func NewLLMReviewCache(root string) LLMReviewCache {
	return LLMReviewCache{root: filepath.Clean(root)}
}

func DefaultLLMReviewCache() (LLMReviewCache, error) {
	paths, err := DefaultPaths()
	if err != nil {
		return LLMReviewCache{}, err
	}
	return NewLLMReviewCache(filepath.Join(paths.Root, "cache", "llm-reviews")), nil
}

func (c LLMReviewCache) Load(key LLMCacheKey) (LLMReview, bool, error) {
	if err := validateLLMCacheKey(key); err != nil {
		return LLMReview{}, false, err
	}
	body, err := os.ReadFile(c.path(key))
	if os.IsNotExist(err) {
		return LLMReview{}, false, nil
	}
	if err != nil {
		return LLMReview{}, false, err
	}
	var review LLMReview
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&review); err != nil {
		return LLMReview{}, false, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("llm cache contains trailing JSON")
		}
		return LLMReview{}, false, err
	}
	if err := validateLLMCacheReview(key, review); err != nil {
		return LLMReview{}, false, err
	}
	review = sanitizeLLMReviewForPersistence(review)
	return review, true, nil
}

func (c LLMReviewCache) Store(key LLMCacheKey, review LLMReview) error {
	if err := validateLLMCacheKey(key); err != nil {
		return err
	}
	if err := validateLLMCacheReview(key, review); err != nil {
		return err
	}
	review = sanitizeLLMReviewForPersistence(review)
	if err := os.MkdirAll(c.root, 0o700); err != nil {
		return err
	}
	body, err := json.MarshalIndent(review, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	tmp, err := os.CreateTemp(c.root, ".llm-review-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, c.path(key))
}

func (c LLMReviewCache) path(key LLMCacheKey) string {
	return filepath.Join(c.root, llmReviewCacheFileName(key))
}

func validateLLMCacheReview(key LLMCacheKey, review LLMReview) error {
	if key.Schema != review.Schema {
		return fmt.Errorf("llm cache schema mismatch")
	}
	return ValidateLLMReview(review, key.EvidenceSHA256)
}

func validateLLMCacheKey(key LLMCacheKey) error {
	if strings.TrimSpace(key.Provider) == "" {
		return fmt.Errorf("llm cache provider is required")
	}
	if strings.TrimSpace(key.Model) == "" {
		return fmt.Errorf("llm cache model is required")
	}
	if strings.TrimSpace(key.Schema) == "" {
		return fmt.Errorf("llm cache schema is required")
	}
	if strings.TrimSpace(key.Schema) != LLMReviewSchema {
		return fmt.Errorf("invalid llm cache schema %q", key.Schema)
	}
	if strings.TrimSpace(key.EvidenceSHA256) == "" {
		return fmt.Errorf("llm cache evidence_sha256 is required")
	}
	if !isLowerSHA256Hex(key.EvidenceSHA256) {
		return fmt.Errorf("invalid llm cache evidence_sha256 %q", key.EvidenceSHA256)
	}
	return nil
}

func llmReviewCacheFileName(key LLMCacheKey) string {
	normalized := struct {
		Provider       string `json:"provider"`
		Model          string `json:"model"`
		Schema         string `json:"schema"`
		EvidenceSHA256 string `json:"evidence_sha256"`
	}{
		Provider:       strings.TrimSpace(key.Provider),
		Model:          strings.TrimSpace(key.Model),
		Schema:         strings.TrimSpace(key.Schema),
		EvidenceSHA256: strings.TrimSpace(key.EvidenceSHA256),
	}
	body, _ := json.Marshal(normalized)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]) + ".json"
}
