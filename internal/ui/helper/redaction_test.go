package helper

import (
	"bufio"
	"io"
	"strings"
	"testing"
)

type discardCloser struct{ io.Writer }

func (discardCloser) Close() error { return nil }

func TestMalformedResponseDoesNotExposeSecret(t *testing.T) {
	for _, reply := range []string{
		"{\"ok\":true,\"answer\":\"sensitive-test-password\" BROKEN}\n",
		"{\"ok\":true,\"answer\":\"sensitive-test-password\",\"remember\":\"private-invalid-value\"}\n",
	} {
		c := &Client{stdin: discardCloser{io.Discard}, stdout: bufio.NewReader(strings.NewReader(reply))}
		_, err := c.call(request{Op: "secret"})
		if err == nil {
			t.Fatal("invalid response accepted")
		}
		if strings.Contains(err.Error(), "sensitive") || strings.Contains(err.Error(), "private-invalid") {
			t.Fatalf("secret leaked: %s", err)
		}
	}
}
