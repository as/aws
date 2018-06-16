// Package ecr helps you get your containers metadata at
// runtime by calling the AWS internal endpoints. No config
// required, just call Stats() to return information about the
// container your process is running in
package ecr

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"
)

var (
	// Marinate for duration before sending first query.
	// Illegal to modify outside init functions scopes
	Marinate = time.Second * 5

	// Timeout http requests after this duration
	Timeout = time.Second * 5
)

var (
	ready  = make(chan struct{})
	client = &http.Client{
		Timeout: 5 * time.Second,
	}
	containerID = regexp.MustCompile(`[0-9a-f]{9,64}`)
)

func init() {
	go func() {
		time.Sleep(Marinate)
		close(ready)
	}()
}

// ErrNotDocker means the cpuset isnt a docker id
var (
	ErrNotDocker = errors.New("cpuset without docker id")
	ErrNoID      = errors.New("phase error: no nested docker id")
)

type (
	// ProcFSError means you cant open fs
	ProcFSError struct{ Err error }

	// QueryError is a problem with the ECR HTTP query
	QueryError struct{ Err error }

	// DataError means ECR returned garbage
	DataError struct{ Err error }
)

// Error implements error
func (e ProcFSError) Error() string { return fmt.Sprintf("procfs: %v", e.Err) }
func (e QueryError) Error() string  { return fmt.Sprintf("stats: %v", e.Err) }
func (e DataError) Error() string   { return fmt.Sprintf("data: %v", e.Err) }
