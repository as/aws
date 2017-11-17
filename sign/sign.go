package sign

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

var (
	RQversion   = "aws4_request"
	DefaultHash = HashFunc{
		Name: "AWS4-HMAC-SHA256",
		Func: sha256.New,
	}
)

// NewSigner returns a signer for the region+service that signs
// a request. The given list of headers specifies which http headers
// are to be signed in a request. 
func NewSigner(region, service string, keys Key, headers ...string) *Signer{
	return &Signer{
		Region: region,
		Service: service,
		Key: Key,
		Headers: List(headers),
	}
}

// SignRequest signs the http request at the current instance
// in time, as given by time.Now()
func (s *Signer) SignRequest(r *http.Request) *http.Request {
	return SignRequestAt(r *http.Request, time.Now())
}

// SignRequestAt signs the http request for the given time instance. The
// request is returned immediately but will only be valid at the given time
func (s *Signer) SignRequestAt(r *http.Request, t time.Time) *http.Request {
	m := s.createMessage(r, t)
	k := s.Gen(t)

	sig := s.Sign(k, m)
	r.Header.Set("Authorization", s.Authorization(sig, t))
	return r
}

// SetHeaders sets the headers to be signed in future calls to SignRequest
// and friends
func (s *Singer) SetHeaders(header ...string){
	s.Headers = List(headers)
}

type Signer struct {
	Region    string
	Service   string
	Key       Key
	Headers   List
	Algorithm *HashFunc
}
type Key struct {
	Access string
	Secret string
}
type HashFunc struct {
	Name string
	Func func() hash.Hash
}

func (h HashFunc) String() string {
	return h.Name
}

func (s *Signer) hash(msg []byte) []byte {
	x := s.alg().Func()
	x.Write(msg)
	return x.Sum(nil)
}

func (s *Signer) Mac(key, msg []byte) []byte {
	return s.mac(key,msg)
}
func (s *Signer) mac(key, msg []byte) []byte {
	x := hmac.New(s.alg().Func, key)
	x.Write(msg)
	return x.Sum(nil)
}

var tohex = hex.EncodeToString

func (s *Signer) Gen(t time.Time) []byte {
	return Gen(Mac(s.mac), t, s.Key.Secret, s.Region, s.Service)
}

func (s *Signer) Sign(key []byte, msg string) string {
	return tohex(s.mac(key, []byte(msg)))
}

func (s *Signer) Authorization(signature string, t time.Time) string {
	return fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s.alg(),
		s.Key.Access,
		s.Scope(t),
		s.Headers,
		signature,
	)
}

type Mac func([]byte, []byte) []byte

func Gen(mac Mac, t time.Time, secret, region, service string) []byte {
	return gen(mac, "AWS4"+secret, shorttime(t), region, service, RQversion)
}
func (s *Signer) Scope(t time.Time) string {
	return fmt.Sprintf("%s/%s/%s/aws4_request", shorttime(t), s.Region, s.Service)
}

func gen(mac Mac, input ...string) []byte {
	if len(input) < 2 {
		panic("gen: internal error: bad input")
	}
	k := []byte(input[0])
	input = input[1:]
	for _, m := range input {
		k = mac(k, []byte(m))
	}
	return k
}

func (s *Signer) createMessage(r *http.Request, t time.Time) string {
	return fmt.Sprintf("%s\n%s\n%s\n%s",
		s.alg(),
		longtime(t),
		s.Scope(t),
		s.normalize(r, t),
	)
}

func toLowerCopy(h http.Header) http.Header {
	h2 := make(http.Header, len(h))
	for k, v := range h {
		h2[strings.TrimSpace(strings.ToLower(k))] = v
	}
	return h2
}

func (s *Signer) normalizeHeaders(headers http.Header) string {
	sort.Strings([]string(s.Headers))
	for i, v := range s.Headers {
		s.Headers[i] = strings.ToLower(v)
	}
	norm := toLowerCopy(headers)
	buf := new(bytes.Buffer)
	for _, k := range s.Headers {
		v, ok := norm[k]
		if !ok {
			panic(v)
		}
		// Append the lowercase header name followed by a colon.
		fmt.Fprintf(buf, "%s:", k)

		// Append a comma-separated list of values for that header.
		// Do not sort the values in headers that have multiple values.
		semi := ""
		for _, v := range v {
			fmt.Fprint(buf, semi)
			fmt.Fprintf(buf, "%s", v)
			semi = ";"
		}

		// Append a new line ('\n').
		fmt.Fprintln(buf)
	}

	return buf.String()
}

func (s *Signer) normalize(r *http.Request, t time.Time) string {
	buf := new(bytes.Buffer)
	normParams := normURL(r.URL.Query())
	normHeaders := s.normalizeHeaders(r.Header)

	for _, v := range []string{r.Method, r.URL.Path, normParams, normHeaders, s.Headers.String()} {
		fmt.Fprintln(buf, v)
	}
	body := ToBuffer(r.Body)
	r.Body = ioutil.NopCloser(body)
	fmt.Fprintf(buf, "%x", s.hash(body.Bytes()))
	return fmt.Sprintf("%x", s.hash(buf.Bytes()))
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
func (k *Signer) alg() *HashFunc {
	if k.Algorithm == nil {
		x := DefaultHash
		k.Algorithm = &x
	}
	return k.Algorithm
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
