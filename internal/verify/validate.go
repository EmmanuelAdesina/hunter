package verify

import (
	"fmt"
	"strings"
)

// hedgeTokens are the words that turn a fact into a maybe.
//
// A notification that says a program "may be accepting reports" tells the
// reader nothing they can act on, and dresses an unverified claim as a
// cautious one. The system does not send those: an unsupported claim is
// withheld instead.
var hedgeTokens = []string{
	"may have", "may be", "might", "possibly", "perhaps", "appears to",
	"seems to", "seems ", "unclear", "we think", "not sure", "could be",
	"presumably", "probably", "likely", "i believe", "it is possible",
}

// maxSubjectLength and maxBodyLength bound the message so that a verbose
// reader cannot turn a notification into an essay.
const (
	maxSubjectLength = 200
	maxBodyLength    = 4000
)

// validate checks a reader's answer against the evidence and the shape.
//
// It returns the violations it found. An empty result means the answer may be
// used as it stands. Every check here is mechanical on purpose: the model's
// own judgement is not trusted, because the point of the stage is to have
// something that is not the model decide whether the model's answer is usable.
func validate(res Result, ev Evidence) []string {
	var problems []string

	switch res.Decision {
	case DecisionAllow:
	case DecisionSuppress:
		if strings.TrimSpace(res.Reason) == "" {
			problems = append(problems, "a suppression must name the fact that contradicts the claim or the fact that is missing")
		}
		return problems
	default:
		return []string{fmt.Sprintf("decision %q is not one of allow or suppress", res.Decision)}
	}

	if strings.TrimSpace(res.Subject) == "" {
		problems = append(problems, "the subject is empty")
	} else if len(res.Subject) > maxSubjectLength {
		problems = append(problems, "the subject is too long")
	}

	if strings.TrimSpace(res.Body) == "" {
		problems = append(problems, "the body is empty")
	} else if len(res.Body) > maxBodyLength {
		problems = append(problems, "the body is too long")
	}

	if len(res.Claims) == 0 {
		problems = append(problems, "the message cites no claims")
	}

	for i, c := range res.Claims {
		if strings.TrimSpace(c.Statement) == "" {
			problems = append(problems, fmt.Sprintf("claim %d has no statement", i+1))
		}
		if c.Verdict != VerdictSupported {
			problems = append(problems, fmt.Sprintf("claim %d is %q, so the message cannot be delivered", i+1, c.Verdict))
		}
		if len(c.Evidence) == 0 {
			problems = append(problems, fmt.Sprintf("claim %d cites no evidence", i+1))
		}
		for _, key := range c.Evidence {
			if _, ok := ev.Fact(key); !ok {
				problems = append(problems, fmt.Sprintf("claim %d cites %q, which is not a fact in the bundle", i+1, key))
			}
		}
	}

	problems = append(problems, hedgeProblems(res.Subject, "subject")...)
	problems = append(problems, hedgeProblems(res.Body, "body")...)

	return problems
}

// hedgeProblems reports the hedging words in a message.
func hedgeProblems(text, what string) []string {
	lower := strings.ToLower(text)
	var found []string
	for _, token := range hedgeTokens {
		if strings.Contains(lower, token) {
			found = append(found, fmt.Sprintf("the %s hedges with %q; a claim that cannot be stated as a fact must be withheld instead", what, strings.TrimSpace(token)))
		}
	}
	return found
}
