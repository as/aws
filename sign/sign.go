package sign

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	RQversion = "aws4_request"
	Algorithm = "AWS4-HMAC-SHA256"
)
func HASH(data string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(data)))
}

func HMAC(key, data string) string {
    x := hmac.New(sha256.New, []byte(key))
    x.Write([]byte(data))
    return string(x.Sum(nil))
}
type Key struct {
	Access string
	Secret string
}
type Signer struct {
	Region  string
	Service string
	Key     Key
	Headers List
}

var tohex = hex.EncodeToString

func Gen(t time.Time, secret, region, service string) []byte{
	return []byte(HMAC(HMAC(HMAC(HMAC("AWS4"+secret, shorttime(t)), region), service), RQversion))
}

func (k *Signer) Gen(t time.Time) []byte {
	return Gen(t, k.Key.Secret, k.Region, k.Service)
}

func (s *Signer) Sign(key []byte, message string) string{
	return tohex([]byte(HMAC(string(key), message)))
}

func (s *Signer) SignRequest(r *http.Request) *http.Request {
	t := time.Now()
	m := s.createMessage(r, t)
	k := s.Gen(t)
	
	sig := s.Sign(k, m)
	r.Header.Set("Authority", s.Authority(sig, t))
	return r
}

func (s *Signer) Authority(signature string, t time.Time) string {
	return fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		Algorithm,
		s.Key.Access,
		s.Scope(t),
		s.Headers,
		signature,
	)
}

func (s *Signer) Scope(t time.Time) string {
	return fmt.Sprintf("%s/%s/%s/aws4_request", shorttime(t), s.Region, s.Service)
}

func (s *Signer) createMessage(r *http.Request, t time.Time) string {
	return fmt.Sprintf("%s\n%s\n%s\n%s\n",
		Algorithm,
		longtime(t),
		s.Scope(t),
		s.normalize(r, t),
	)
}

func (s *Signer) normalizeHeaders(headers http.Header) string {
	h2 := make(http.Header)
	seen := make([]string, 0, len(s.Headers))
	sort.Strings([]string(s.Headers))
	for _, k := range s.Headers {
		v := headers.Get(k)

		// Convert all header names to lowercase and remove leading spaces and trailing spaces.
		k = strings.TrimSpace(strings.ToLower(k))

		// TODO: Convert sequential spaces in the header value to a single space.
		h2[k] = []string{v}

		seen = append(seen, k)
	}

	buf := new(bytes.Buffer)

	sort.Strings(seen)
	for _, k := range seen {
		// Append the lowercase header name followed by a colon.
		fmt.Fprintf(buf, "%s:", k)

		// Append a comma-separated list of values for that header.
		// Do not sort the values in headers that have multiple values.
		values := h2[k]
		for i, v := range values {
			fmt.Fprintf(buf, "%s", v)
			if i+1 == len(values) {
				break
			}
			fmt.Fprint(buf, ";")
		}
		// Append a new line ('\n').
		fmt.Fprint(buf, "\n")
	}
	return buf.String()
}

func (s *Signer) normalize(r *http.Request, t time.Time) string {
	buf := new(bytes.Buffer)
	for _, v := range []string{r.Method, r.URL.Path, normURL(r.URL.Query()), s.normalizeHeaders(r.Header), s.Headers.String()} {
		fmt.Fprintln(buf, v)
	}
	body := ToBuffer(r.Body)
	r.Body = ioutil.NopCloser(body)
	fmt.Fprint(buf, HASH(string(body.Bytes())))
	return HASH(string(buf.Bytes()))
}

func ToBuffer(r io.Reader) *bytes.Buffer {
	type Byter interface {
		Bytes() []byte
	}
	switch t := r.(type) {
	case *bytes.Buffer:
		return t
	case Byter:
		return bytes.NewBuffer(t.Bytes())
	}
	data, err := ioutil.ReadAll(r)
	if err != nil {
		panic(err)
	}
	return bytes.NewBuffer(data)
}

func normURL(v url.Values) (s string) {
	return "" // TODO
}

func longtime(t time.Time) string {
	return t.UTC().Format("20060102T150405Z")
}
func shorttime(t time.Time) string {
	return t.UTC().Format("20060102")
}

type List []string

func (l List) String() string {
	s := ""
	for i, v := range l {
		s += v
		if i+1 == len(l) {
			break
		}
		s += ";"
	}
	return s
}
