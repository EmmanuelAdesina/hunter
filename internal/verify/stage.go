package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Model is the reader.
//
// It is an interface so that the stage can be tested without a network, and
// so that the provider is a configuration choice rather than a dependency.
type Model interface {
	// Complete returns the reader's raw answer to the prompt.
	Complete(ctx context.Context, system, user string) (string, error)

	// Name identifies the model in logs and records.
	Name() string
}

// StageConfig configures the verification stage.
type StageConfig struct {
	// Model is the reader.
	Model Model

	// SubjectPrefix is prepended to the subject the reader wrote, so the
	// message is still recognizable in a mailbox.
	SubjectPrefix string

	// RepairAttempts is how many times the reader is asked to correct an
	// answer that failed validation. Zero means the first answer is the only
	// answer.
	RepairAttempts int

	// OnUnavailable decides what happens when the reader cannot be reached or
	// returns something unusable: "suppress" withholds the alert, "deliver"
	// falls back to the pipeline's own message. Suppressing is the default
	// because an unverified notification is exactly the failure this stage
	// exists to prevent.
	OnUnavailable string
}

// Stage is the verification stage.
type Stage struct {
	cfg StageConfig
}

// NewStage builds a stage.
func NewStage(cfg StageConfig) (*Stage, error) {
	if cfg.Model == nil {
		return nil, fmt.Errorf("verify: a model is required")
	}
	if cfg.OnUnavailable == "" {
		cfg.OnUnavailable = "suppress"
	}
	switch cfg.OnUnavailable {
	case "suppress", "deliver":
	default:
		return nil, fmt.Errorf("verify: on_unavailable must be suppress or deliver, got %q", cfg.OnUnavailable)
	}
	return &Stage{cfg: cfg}, nil
}

// Name identifies the stage.
func (s *Stage) Name() string { return "llm:" + s.cfg.Model.Name() }

// Verify judges one candidate alert.
//
// The reader is asked once. An answer that fails validation is sent back with
// the specific violations, once, so that a reader which simply misunderstood
// the shape can correct itself. An answer that still fails is not used.
//
// Two outcomes are different in kind and are reported differently. A reader
// that works and decides the claim is false returns a suppression: the alert
// is withheld silently, because that is the stage doing its job. A reader
// that could not be used at all - unreachable, unauthenticated, answering in
// a shape it was not asked for - returns an error, because that is a broken
// configuration and the operator has to hear about it.
func (s *Stage) Verify(ctx context.Context, req Request) (Result, error) {
	ev := buildEvidence(req)
	payload, err := renderEvidence(ev)
	if err != nil {
		return Result{}, err
	}

	user := "Candidate alert:\n" + payload
	attempts := s.cfg.RepairAttempts + 1

	for attempt := 0; attempt < attempts; attempt++ {
		raw, err := s.cfg.Model.Complete(ctx, systemPrompt, user)
		if err != nil {
			return s.unavailable(fmt.Errorf("the reader could not be reached: %w", err))
		}

		res, parseErr := parseResult(raw)
		if parseErr != nil {
			if attempt == attempts-1 {
				return s.unavailable(parseErr)
			}
			user = repairPrompt(payload, []string{parseErr.Error()})
			continue
		}

		if problems := validate(res, ev); len(problems) > 0 {
			if attempt == attempts-1 {
				return s.unavailable(fmt.Errorf("the reader's answer did not hold up: %s", strings.Join(problems, "; ")))
			}
			user = repairPrompt(payload, problems)
			continue
		}

		if res.Decision == DecisionAllow {
			res.Subject = s.cfg.SubjectPrefix + res.Subject
			res.Model = s.cfg.Model.Name()
		}
		return res, nil
	}

	return s.unavailable(fmt.Errorf("the reader produced no usable answer"))
}

// unavailable applies the configured policy for a reader that could not be
// used.
//
// The default withholds the alert and reports the failure, so that a missing
// notification is an auditable decision rather than a gap.
func (s *Stage) unavailable(cause error) (Result, error) {
	if s.cfg.OnUnavailable == "deliver" {
		return Result{
			Decision:  DecisionAllow,
			Reason:    "the reader was unavailable, so the pipeline's own message was kept: " + cause.Error(),
			Unverified: true,
			Model:     s.cfg.Model.Name(),
		}, cause
	}
	return Result{
		Decision: DecisionSuppress,
		Reason:   "withheld because the alert could not be verified: " + cause.Error(),
		Model:    s.cfg.Model.Name(),
	}, cause
}

// repairPrompt asks the reader to fix an answer that failed validation.
func repairPrompt(payload string, problems []string) string {
	var b strings.Builder
	b.WriteString("Candidate alert:\n")
	b.WriteString(payload)
	b.WriteString("\n\nYour previous answer was not usable:\n")
	for _, p := range problems {
		b.WriteString("- ")
		b.WriteString(p)
		b.WriteString("\n")
	}
	b.WriteString("\nAnswer again with the same JSON shape, obeying every rule.")
	return b.String()
}

// parseResult reads the reader's answer.
//
// The answer must be JSON. A reader that wraps its answer in prose has not
// followed the contract, and an answer that cannot be read is not used.
func parseResult(raw string) (Result, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return Result{}, fmt.Errorf("the reader returned nothing")
	}
	if start := strings.Index(trimmed, "{"); start > 0 {
		trimmed = trimmed[start:]
	}
	if end := strings.LastIndex(trimmed, "}"); end >= 0 && end < len(trimmed)-1 {
		trimmed = trimmed[:end+1]
	}

	var res Result
	dec := json.NewDecoder(strings.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&res); err != nil {
		return Result{}, fmt.Errorf("the reader's answer is not the agreed shape: %w", err)
	}
	return res, nil
}
