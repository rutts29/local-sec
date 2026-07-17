package lsec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultOllamaBaseURL = "http://localhost:11434"

type OllamaReviewConfig struct {
	BaseURL string
	Model   string
	Timeout time.Duration
}

type ollamaGenerateRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type ollamaGenerateResponse struct {
	Response string `json:"response"`
}

func ReviewWithOllama(ctx context.Context, cfg OllamaReviewConfig, bundle EvidenceBundle) (LLMReview, error) {
	client := http.DefaultClient
	if cfg.Timeout > 0 {
		client = &http.Client{Timeout: cfg.Timeout}
	}
	return reviewWithOllamaHTTPClient(ctx, cfg, bundle, client)
}

func reviewWithOllamaHTTPClient(ctx context.Context, cfg OllamaReviewConfig, bundle EvidenceBundle, client *http.Client) (LLMReview, error) {
	if strings.TrimSpace(cfg.Model) == "" {
		return LLMReview{}, fmt.Errorf("ollama model is required")
	}
	client = ollamaNoRedirectClient(client)
	base, err := ollamaBaseURL(cfg.BaseURL)
	if err != nil {
		return LLMReview{}, err
	}
	prompt, evidenceSHA256, err := BuildLLMReviewPrompt(bundle)
	if err != nil {
		return LLMReview{}, err
	}

	body, err := json.Marshal(ollamaGenerateRequest{
		Model:  cfg.Model,
		Prompt: prompt,
		Stream: false,
	})
	if err != nil {
		return LLMReview{}, err
	}

	endpoint := *base
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/api/generate"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return LLMReview{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		return LLMReview{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return LLMReview{}, fmt.Errorf("ollama generate failed: %s", resp.Status)
	}

	var generated ollamaGenerateResponse
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&generated); err != nil {
		return LLMReview{}, err
	}
	return ParseLLMReviewOutput([]byte(generated.Response), evidenceSHA256)
}

func ollamaNoRedirectClient(client *http.Client) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}
	guarded := *client
	guarded.CheckRedirect = func(*http.Request, []*http.Request) error {
		return fmt.Errorf("ollama redirect rejected")
	}
	return &guarded
}

func ollamaBaseURL(raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		raw = defaultOllamaBaseURL
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" {
		u.Scheme = "http"
	}
	if u.Host == "" {
		return nil, fmt.Errorf("ollama base URL must include a host")
	}
	if u.User != nil {
		return nil, fmt.Errorf("ollama base URL must not include userinfo")
	}
	host := strings.ToLower(u.Hostname())
	switch host {
	case "localhost", "127.0.0.1", "::1":
	default:
		return nil, fmt.Errorf("ollama base URL must be loopback")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("ollama base URL scheme must be http or https")
	}
	return u, nil
}
