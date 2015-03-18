package manager

import (
	"fmt"
	"time"

	"github.com/samalba/dockerclient"
	"github.com/shipyard/shipyard"
)

type (
	EventHandler struct {
		Manager Manager
	}
)

func (h *EventHandler) Handle(e *dockerclient.Event) error {
	logger.Infof("event: date=%s status=%s container=%s", time.Unix(e.Time, 0), e.Status, e.From[:12])
	h.logDockerEvent(e)
	return nil
}

func (h *EventHandler) logDockerEvent(e *dockerclient.Event) error {
	cInfo, err := h.Manager.Container(e.From)
	if err != nil {
		return err
	}
	evt := &shipyard.Event{
		Type: e.Status,
		Message: fmt.Sprintf("action=%s container=%s",
			e.Status, e.From[:12]),
		Time:      time.Unix(e.Time, 0),
		Container: cInfo,
		Tags:      []string{"docker"},
	}
	if err := h.Manager.SaveEvent(evt); err != nil {
		return err
	}
	return nil
}
