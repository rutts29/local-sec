package lsec

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOllamaReviewDefaultLoopbackURLAcceptedAndPostsGenerateRequest(t *testing.T) {
	var sawRequest bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawRequest = true
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/api/generate" {
			t.Fatalf("path = %s, want /api/generate", r.URL.Path)
		}
		var req ollamaGenerateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.Model != "local-reviewer" {
			t.Fatalf("model = %q, want local-reviewer", req.Model)
		}
		if req.Stream {
			t.Fatal("stream = true, want false")
		}
		for _, want := range []string{LLMReviewSchema, `"evidence_sha256"`, "Evidence JSON:"} {
			if !strings.Contains(req.Prompt, want) {
				t.Fatalf("prompt missing %q: %s", want, req.Prompt)
			}
		}
		hash := hashFromPrompt(t, req.Prompt)
		writeOllamaResponse(t, w, validLLMReviewJSON(hash))
	}))
	defer server.Close()

	review, err := ReviewWithOllama(context.Background(), OllamaReviewConfig{
		BaseURL: server.URL,
		Model:   "local-reviewer",
	}, ollamaTestBundle())
	if err != nil {
		t.Fatal(err)
	}
	if !sawRequest {
		t.Fatal("server did not receive request")
	}
	if review.Verdict != VerdictPrompt {
		t.Fatalf("verdict = %s, want prompt", review.Verdict)
	}
}

func TestOllamaReviewRejectsRemoteURLBeforeRequest(t *testing.T) {
	called := false
	client := &http.Client{Transport: ollamaRoundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, nil
	})}

	_, err := reviewWithOllamaHTTPClient(context.Background(), OllamaReviewConfig{
		BaseURL: "http://example.com:11434",
		Model:   "local-reviewer",
	}, ollamaTestBundle(), client)
	if err == nil {
		t.Fatal("remote URL accepted")
	}
	if called {
		t.Fatal("remote URL made an HTTP request")
	}
}

func TestOllamaReviewRejectsRedirectBeforeRemoteRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/collect", http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	remoteReached := false
	client := server.Client()
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	client.Transport = ollamaRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Hostname() == "example.com" {
			remoteReached = true
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Body:       io.NopCloser(strings.NewReader(`{"response":"{}"}`)),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}
		return transport.RoundTrip(req)
	})

	_, err := reviewWithOllamaHTTPClient(context.Background(), OllamaReviewConfig{
		BaseURL: server.URL,
		Model:   "local-reviewer",
	}, ollamaTestBundle(), client)
	if err == nil {
		t.Fatal("redirect accepted")
	}
	if remoteReached {
		t.Fatal("redirect target received Ollama review request")
	}
}

func TestOllamaReviewMalformedOllamaJSONFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"response":`))
	}))
	defer server.Close()

	if _, err := ReviewWithOllama(context.Background(), OllamaReviewConfig{
		BaseURL: server.URL,
		Model:   "local-reviewer",
	}, ollamaTestBundle()); err == nil {
		t.Fatal("malformed Ollama JSON accepted")
	}
}

func TestOllamaReviewUnknownFieldsInReviewResponseFail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hash := hashFromRequestPrompt(t, r)
		writeOllamaResponse(t, w, `{
			"schema": "lsec.llm_review",
			"version": 1,
			"evidence_sha256": "`+hash+`",
			"verdict": "prompt",
			"confidence": "medium",
			"reasons": ["credential exfiltration signal"],
			"signals": ["network canary"],
			"unexpected": true
		}`)
	}))
	defer server.Close()

	if _, err := ReviewWithOllama(context.Background(), OllamaReviewConfig{
		BaseURL: server.URL,
		Model:   "local-reviewer",
	}, ollamaTestBundle()); err == nil {
		t.Fatal("review with unknown field accepted")
	}
}

func TestOllamaReviewTrailingContentInReviewResponseFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hash := hashFromRequestPrompt(t, r)
		writeOllamaResponse(t, w, validLLMReviewJSON(hash)+"\nAdditional explanation.")
	}))
	defer server.Close()

	if _, err := ReviewWithOllama(context.Background(), OllamaReviewConfig{
		BaseURL: server.URL,
		Model:   "local-reviewer",
	}, ollamaTestBundle()); err == nil {
		t.Fatal("review response with trailing content accepted")
	}
}

func TestOllamaReviewHashMismatchFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeOllamaResponse(t, w, validLLMReviewJSON(strings.Repeat("b", 64)))
	}))
	defer server.Close()

	if _, err := ReviewWithOllama(context.Background(), OllamaReviewConfig{
		BaseURL: server.URL,
		Model:   "local-reviewer",
	}, ollamaTestBundle()); err == nil {
		t.Fatal("review with mismatched hash accepted")
	}
}

func TestOllamaBaseURLDefaultsToLocalhost(t *testing.T) {
	u, err := ollamaBaseURL("")
	if err != nil {
		t.Fatal(err)
	}
	if got := u.String(); got != "http://localhost:11434" {
		t.Fatalf("base URL = %q, want http://localhost:11434", got)
	}
}

func TestOllamaBaseURLAcceptsIPv6Loopback(t *testing.T) {
	u, err := ollamaBaseURL("http://[::1]:11434")
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Hostname(); got != "::1" {
		t.Fatalf("hostname = %q, want ::1", got)
	}
}

func TestOllamaReviewValidFakeResponseReturnsParsedReview(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hash := hashFromRequestPrompt(t, r)
		writeOllamaResponse(t, w, validLLMReviewJSON(hash))
	}))
	defer server.Close()

	review, err := ReviewWithOllama(context.Background(), OllamaReviewConfig{
		BaseURL: server.URL,
		Model:   "local-reviewer",
	}, ollamaTestBundle())
	if err != nil {
		t.Fatal(err)
	}
	if review.Schema != LLMReviewSchema || review.EvidenceSHA256 == "" || review.Verdict != VerdictPrompt {
		t.Fatalf("review = %#v", review)
	}
}

func hashFromRequestPrompt(t *testing.T, r *http.Request) string {
	t.Helper()
	var req ollamaGenerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		t.Fatal(err)
	}
	return hashFromPrompt(t, req.Prompt)
}

func hashFromPrompt(t *testing.T, prompt string) string {
	t.Helper()
	marker := `"evidence_sha256": "`
	start := strings.Index(prompt, marker)
	if start == -1 {
		t.Fatalf("prompt missing evidence hash: %s", prompt)
	}
	start += len(marker)
	end := strings.Index(prompt[start:], `"`)
	if end == -1 {
		t.Fatalf("prompt has unterminated evidence hash: %s", prompt)
	}
	return prompt[start : start+end]
}

func writeOllamaResponse(t *testing.T, w http.ResponseWriter, response string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(ollamaGenerateResponse{Response: response}); err != nil {
		t.Fatal(err)
	}
}

func validLLMReviewJSON(hash string) string {
	return `{
		"schema": "lsec.llm_review",
		"version": 1,
		"evidence_sha256": "` + hash + `",
		"verdict": "prompt",
		"confidence": "medium",
		"reasons": ["credential exfiltration signal"],
		"signals": ["network canary"]
	}`
}

func ollamaTestBundle() EvidenceBundle {
	return EvidenceBundle{
		RunID: "run-ollama-review",
		Analysis: CommandAnalysis{
			Manager: "npm",
			PackageSpecs: []PackageSpec{{
				Name:    "demo-package",
				Version: "1.0.0",
			}},
		},
		Decision: Decision{Verdict: VerdictAllow, Lane: LaneTrusted, Reasons: []string{"no blocking or prompting signals found"}},
	}
}

type ollamaRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn ollamaRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}
