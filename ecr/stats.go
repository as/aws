package ecr

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"time"
)

// Container information
type Container struct {
	ID         string `json:"DockerId"`
	Name       string
	DockerName string
	Image      string
	ImageID    string
	Type       string
	Labels     map[string]string

	DesiredStatus string
	KnownStatus   string
	CreatedAt     time.Time
	StartedAt     time.Time
	FinishedAt    time.Time
	ExitCode      *int

	Limits struct {
		CPU    float64
		Memory int64
	}
	Network struct {
		Mode string   `json:"NetworkMode"`
		IPv4 []string `json:"IPv4Addresses"`
		IPv6 []string `json:"IPv6Addresses"`
	}
	Ports []struct {
		Container int `json:"ContainerPort"`
		Host      int `json:"HostPort"`
		Protocol  string
	}
}

// Stats returns the running container's information including
// the port mappings associated with the container at
// runtime, if applicable.
func Stats() (c *Container, err error) {
	x, err := ioutil.ReadFile("/proc/1/cpuset")
	if err != nil {
		return nil, ProcFSError{err}
	}

	id := filepath.Base(string(x))
	if !containerID.MatchString(id) {
		return nil, ErrNotDocker
	}
	<-ready

	r, err := client.Get(fmt.Sprintf("http://169.254.170.2/v2/stats/%s", id))
	if err != nil {
		return nil, QueryError{err}
	}
	if c := r.StatusCode; c != 200 {
		return nil, QueryError{fmt.Errorf("bad response: %v", c)}
	}

	defer r.Body.Close()
	if err = json.NewDecoder(r.Body).Decode(c); err != nil {
		return nil, DataError{err}
	}

	return c, nil
}
