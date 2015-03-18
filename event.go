package shipyard

import (
	"time"

	"github.com/samalba/dockerclient"
)

type Event struct {
	Type      string                      `json:"type,omitempty"`
	Container *dockerclient.ContainerInfo `json:"container,omitempty"`
	Time      time.Time                   `json:"time,omitempty"`
	Message   string                      `json:"message,omitempty"`
	Tags      []string                    `json:"tags,omitempty"`
}
