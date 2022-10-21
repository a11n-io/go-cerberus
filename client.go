package go_cerberus

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type errorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type successResponse struct {
	Code int         `json:"code"`
	Data interface{} `json:"data"`
}

type Client interface {
	GetToken(ctx context.Context) (string, error)
}

type client struct {
	baseURL    string
	apiKey     string
	apiSecret  string
	HTTPClient *http.Client
}

func NewClient(baseUrl, apiKey, apiSecret string) Client {
	return &client{
		baseURL:   baseUrl,
		apiKey:    apiKey,
		apiSecret: apiSecret,
		HTTPClient: &http.Client{
			Timeout: time.Minute,
		},
	}
}

func (c *client) GetToken(ctx context.Context) (string, error) {

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/auth/token", c.baseURL), nil)
	if err != nil {
		return "", err
	}

	req = req.WithContext(ctx)

	var token string
	if err := c.sendRequest(req, &token); err != nil {
		return "", err
	}

	return token, nil
}

func (c *client) sendRequest(req *http.Request, v interface{}) error {

	authStr := c.apiKey + ":" + c.apiSecret
	auth := base64.StdEncoding.EncodeToString([]byte(authStr))

	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Accept", "application/json; charset=utf-8")
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", auth))

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusBadRequest {
		var errRes errorResponse
		if err = json.NewDecoder(res.Body).Decode(&errRes); err == nil {
			return errors.New(errRes.Message)
		}

		return fmt.Errorf("unknown error, status code: %d", res.StatusCode)
	}

	fullResponse := successResponse{
		Data: v,
	}
	if err = json.NewDecoder(res.Body).Decode(&fullResponse); err != nil {
		return err
	}

	return nil
}
