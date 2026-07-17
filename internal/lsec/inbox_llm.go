package lsec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const inboxLLMReviewKind = "llm_review"

type inboxLLMReviewEvent struct {
	RunID             string    `json:"run_id"`
	Review            LLMReview `json:"review"`
	EvidenceSHA256    string    `json:"evidence_sha256"`
	Provider          string    `json:"provider"`
	Model             string    `json:"model"`
	Cached            bool      `json:"cached"`
	EffectiveDecision Decision  `json:"effective_decision"`
	CreatedAt         time.Time `json:"created_at"`
}

type inboxLLMReviewOptions struct {
	RunID   string
	Model   string
	BaseURL string
	Timeout time.Duration
}

type inboxLLMReviewOutput struct {
	RunID             string    `json:"run_id"`
	Cached            bool      `json:"cached"`
	Review            LLMReview `json:"review"`
	EffectiveDecision Decision  `json:"effective_decision"`
	EffectiveVerdict  Verdict   `json:"effective_verdict"`
	EffectiveLane     RiskLane  `json:"effective_lane"`
	EffectiveReasons  []string  `json:"effective_reasons"`
}

func runInboxReviewLLM(args []string, stdout io.Writer, store Store) error {
	opts, err := parseInboxLLMReviewOptions(args)
	if err != nil {
		return err
	}
	report, ok, err := store.LoadRunReport(opts.RunID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("run %q not found", opts.RunID)
	}
	if _, err := ollamaBaseURL(opts.BaseURL); err != nil {
		return err
	}
	bundle := BuildEvidenceBundle(report)
	cache, err := DefaultLLMReviewCache()
	if err != nil {
		return err
	}
	key := LLMCacheKey{
		Provider:       "ollama",
		Model:          opts.Model,
		Schema:         LLMReviewSchema,
		EvidenceSHA256: bundle.EvidenceSHA256,
	}

	review, cached, err := cache.Load(key)
	if err != nil {
		return err
	}
	if !cached {
		review, err = ReviewWithOllama(context.Background(), OllamaReviewConfig{
			BaseURL: opts.BaseURL,
			Model:   opts.Model,
			Timeout: opts.Timeout,
		}, bundle)
		if err != nil {
			return err
		}
		review = sanitizeLLMReviewForPersistence(review)
		if err := cache.Store(key, review); err != nil {
			return err
		}
	}
	effective := ApplyLLMReview(report.Decision, review)
	event := sanitizeInboxLLMReviewEvent(inboxLLMReviewEvent{
		RunID:             report.RunID,
		Review:            review,
		EvidenceSHA256:    bundle.EvidenceSHA256,
		Provider:          "ollama",
		Model:             opts.Model,
		Cached:            cached,
		EffectiveDecision: effective,
		CreatedAt:         time.Now().UTC(),
	})
	if err := store.AppendEvent(inboxLLMReviewKind, event); err != nil {
		return err
	}

	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(inboxLLMReviewOutput{
		RunID:             report.RunID,
		Cached:            cached,
		Review:            event.Review,
		EffectiveDecision: event.EffectiveDecision,
		EffectiveVerdict:  event.EffectiveDecision.Verdict,
		EffectiveLane:     event.EffectiveDecision.Lane,
		EffectiveReasons:  event.EffectiveDecision.Reasons,
	})
}

func parseInboxLLMReviewOptions(args []string) (inboxLLMReviewOptions, error) {
	if len(args) == 0 {
		return inboxLLMReviewOptions{}, errors.New("inbox review-llm requires run_id --model <model> [--base-url <loopback-url>] [--timeout <duration>]")
	}
	opts := inboxLLMReviewOptions{RunID: args[0]}
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--model":
			i++
			if i >= len(args) || strings.TrimSpace(args[i]) == "" {
				return inboxLLMReviewOptions{}, errors.New("inbox review-llm --model requires a value")
			}
			opts.Model = args[i]
		case "--base-url":
			i++
			if i >= len(args) || strings.TrimSpace(args[i]) == "" {
				return inboxLLMReviewOptions{}, errors.New("inbox review-llm --base-url requires a value")
			}
			opts.BaseURL = args[i]
		case "--timeout":
			i++
			if i >= len(args) || strings.TrimSpace(args[i]) == "" {
				return inboxLLMReviewOptions{}, errors.New("inbox review-llm --timeout requires a value")
			}
			timeout, err := time.ParseDuration(args[i])
			if err != nil {
				return inboxLLMReviewOptions{}, err
			}
			if timeout <= 0 {
				return inboxLLMReviewOptions{}, errors.New("inbox review-llm --timeout must be positive")
			}
			opts.Timeout = timeout
		default:
			return inboxLLMReviewOptions{}, fmt.Errorf("unknown inbox review-llm option %q", args[i])
		}
	}
	if strings.TrimSpace(opts.Model) == "" {
		return inboxLLMReviewOptions{}, errors.New("inbox review-llm --model is required")
	}
	return opts, nil
}

func latestLLMReviewBlocksApproval(store Store, runID, evidenceSHA256 string) (bool, error) {
	var latest inboxLLMReviewEvent
	found := false
	if err := store.eventLog().forEach(func(line []byte) error {
		event, ok := parseInboxLLMReviewEvent(line)
		if !ok || event.RunID != runID || event.EvidenceSHA256 != evidenceSHA256 {
			return nil
		}
		latest = event
		found = true
		return nil
	}); err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	return latest.Review.Verdict == VerdictBlock || latest.EffectiveDecision.Verdict == VerdictBlock, nil
}

func parseInboxLLMReviewEvent(line []byte) (inboxLLMReviewEvent, bool) {
	row, createdAt, ok := parseEventLogRow(line)
	if !ok || row.Kind != inboxLLMReviewKind {
		return inboxLLMReviewEvent{}, false
	}
	var event inboxLLMReviewEvent
	if err := json.Unmarshal(row.JSON, &event); err != nil || event.RunID == "" {
		return inboxLLMReviewEvent{}, false
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = createdAt
	}
	return event, true
}

func sanitizeInboxLLMReviewEvent(event inboxLLMReviewEvent) inboxLLMReviewEvent {
	event.Review = sanitizeLLMReviewForPersistence(event.Review)
	event.EffectiveDecision.Reasons = redactEvidenceTextList(event.EffectiveDecision.Reasons)
	event.Provider = redactEvidenceValue(event.Provider)
	event.Model = redactEvidenceValue(event.Model)
	return event
}

func sanitizeLLMReviewForPersistence(review LLMReview) LLMReview {
	review.Reasons = redactEvidenceTextList(review.Reasons)
	review.Signals = redactEvidenceTextList(review.Signals)
	return review
}

func redactEvidenceTextList(values []string) []string {
	if len(values) == 0 {
		return values
	}
	redacted := append([]string(nil), values...)
	for i := range redacted {
		redacted[i] = redactEvidenceText(redacted[i])
	}
	return redacted
}
