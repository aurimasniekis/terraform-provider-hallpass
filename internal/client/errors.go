package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// FieldError is a per-field validation problem.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// APIError is an RFC 9457 problem returned by HallPass.
type APIError struct {
	StatusCode int          `json:"status"`
	Type       string       `json:"type,omitempty"`
	Title      string       `json:"title,omitempty"`
	Code       string       `json:"code"`
	Instance   string       `json:"instance,omitempty"`
	Errors     []FieldError `json:"errors,omitempty"`

	Method string `json:"-"`
	Path   string `json:"-"`
}

func (e *APIError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "hallpass API %s %s: %d", e.Method, e.Path, e.StatusCode)
	if e.Code != "" {
		b.WriteString(" " + e.Code)
	}
	if e.Title != "" {
		b.WriteString(": " + e.Title)
	}
	if len(e.Errors) > 0 {
		parts := make([]string, 0, len(e.Errors))
		for _, f := range e.Errors {
			parts = append(parts, f.Field+": "+f.Message)
		}
		b.WriteString(" (" + strings.Join(parts, "; ") + ")")
	}
	return b.String()
}

// TransportError is a network-level failure (after retries).
type TransportError struct {
	Method, Path string
	Err          error
}

func (e *TransportError) Error() string {
	return fmt.Sprintf("hallpass API %s %s: %v", e.Method, e.Path, e.Err)
}

func (e *TransportError) Unwrap() error { return e.Err }

// decodeProblem turns an error response into an *APIError. Bodies that are not problem documents are summarised by
// status only (they are never echoed, so a misbehaving proxy cannot leak data into logs).
func decodeProblem(method, path string, resp *response) *APIError {
	e := &APIError{}
	if err := json.Unmarshal(resp.body, e); err != nil || (e.Code == "" && e.Title == "") {
		e = &APIError{Title: http.StatusText(resp.status)}
	}
	e.StatusCode = resp.status
	e.Method, e.Path = method, path
	if e.Code == "" {
		e.Code = defaultCode(resp.status)
	}
	return e
}

func defaultCode(status int) string {
	switch status {
	case http.StatusNotFound:
		return "not_found"
	case http.StatusConflict:
		return "conflict"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusTooManyRequests:
		return "rate_limited"
	}
	if status >= 500 {
		return "internal"
	}
	return ""
}

// IsNotFound reports whether err is a 404 problem.
func IsNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.StatusCode == http.StatusNotFound
}

// HasCode reports whether err is a problem with the given code.
func HasCode(err error, code string) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Code == code
}

// notFound is returned by lookups that scan a list and find nothing.
func notFound(path, what string) *APIError {
	return &APIError{StatusCode: http.StatusNotFound, Code: "not_found", Title: what + " not found", Method: http.MethodGet, Path: path}
}
