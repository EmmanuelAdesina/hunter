package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ClientConfig configures the reader client.
//
// The client speaks the OpenAI chat-completions shape, which is what most
// hosted and self-hosted models expose, so the provider is a configuration
// choice rather than a dependency of the tool.
type ClientConfig struct {
	// BaseURL is the API root, for example https://api.openai.com/v1.
	BaseURL string

	// Model is the model name to request.
	Model string

	// APIKey authenticates the request.
	APIKey string

	// Timeout bounds one request.
	Timeout time.Duration

	// MaxTokens bounds the answer length.
	MaxTokens int

	// Temperature is fixed at zero for reproducibility unless set.
	Temperature float64

	// HTTPClient is used when set.
	HTTPClient *http.Client
}

// Client is a reader backed by an OpenAI-compatible chat endpoint.
type Client struct {
	cfg ClientConfig
}

// NewClient builds a reader client.
func NewClient(cfg ClientConfig) (*Client, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, fmt.Errorf("verify: a base URL is required")
	}
	if strings.TrimSpace(cfg.Model) == "" {
		return nil, fmt.Errorf("verify: a model name is required")
	}
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, fmt.Errorf("verify: an API key is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 60 * time.Second
	}
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = 1200
	}
	return &Client{cfg: cfg}, nil
}

// Name identifies the model.
func (c *Client) Name() string { return c.cfg.Model }

type chatRequest struct {
	Model          string        `json:"model"`
	Messages       []chatMessage `json:"messages"`
	Temperature    float64       `json:"temperature"`
	MaxTokens      int           `json:"max_tokens,omitempty"`
	ResponseFormat *responseFmt  `json:"response_format,omitempty"`
}

type responseFmt struct {
	Type string `json:"type"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
}

// Complete asks the model and returns its answer.
func (c *Client) Complete(ctx context.Context, system, user string) (string, error) {
	body, err := json.Marshal(chatRequest{
		Model: c.cfg.Model,
		Messages: []chatMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
		Temperature:    c.cfg.Temperature,
		MaxTokens:      c.cfg.MaxTokens,
		ResponseFormat: &responseFmt{Type: "json_object"},
	})
	if err != nil {
		return "", fmt.Errorf("encode request: %w", err)
	}

	endpoint := strings.TrimRight(c.cfg.BaseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)

	client := c.cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: c.cfg.Timeout}
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("call model: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	var parsed chatResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", fmt.Errorf("decode response (HTTP %d): %w", resp.StatusCode, err)
	}
	if parsed.Error != nil {
		return "", fmt.Errorf("model error (HTTP %d): %s", resp.StatusCode, parsed.Error.Message)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("model returned HTTP %d", resp.StatusCode)
	}
	if len(parsed.Choices) == 0 {
		return "", fmt.Errorf("model returned no choices")
	}
	return parsed.Choices[0].Message.Content, nil
}
