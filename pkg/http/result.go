package http

import (
	"errors"
	"strings"
)

var (
	ErrHeaderNotFound = errors.New("header not found")
)

type Result[R interface{}] struct {
	StatusCode int
	Headers    map[string]string
	// RawBody contains the raw response body bytes as returned by the server.
	// This is useful for debugging and inspecting the original payload.
	RawBody []byte
	Data    R
}

func (c *Result[R]) GetHeader(key string) (string, error) {
	key = strings.ToLower(key)
	for k, v := range c.Headers {
		if strings.ToLower(k) == key {
			return v, nil
		}
	}

	return "", ErrHeaderNotFound
}
