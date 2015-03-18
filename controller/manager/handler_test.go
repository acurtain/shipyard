package manager

import (
	"testing"
	"time"

	"github.com/samalba/dockerclient"
	"github.com/shipyard/shipyard/controller/mock_test"
)

func TestEventHandle(t *testing.T) {
	m := mock_test.MockManager{}
	h := EventHandler{
		Manager: m,
	}

	evt := &dockerclient.Event{
		Id:     mock_test.TestContainerId,
		Status: "testing",
		From:   mock_test.TestContainerId,
		Time:   time.Now().UnixNano(),
	}

	if err := h.Handle(evt); err != nil {
		t.Fatal(err)
	}
}
