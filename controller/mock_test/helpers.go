package mock_test

import (
	"time"

	"github.com/samalba/dockerclient"
	"github.com/shipyard/shipyard"
	"github.com/shipyard/shipyard/dockerhub"
)

var (
	TestEngineAddr     = "127.0.0.1:2375"
	TestContainerId    = "1234567890abcdefg"
	TestContainerName  = "test-container"
	TestContainerImage = "test-image"
	TestContainerInfo  = &dockerclient.ContainerInfo{
		Id:      TestContainerId,
		Created: string(time.Now().UnixNano()),
		Name:    TestContainerName,
		Image:   TestContainerImage,
	}
	TestEngine = &shipyard.Engine{
		ID:             "12345",
		Addr:           TestEngineAddr,
		CACertificate:  "",
		SSLCertificate: "",
		SSLKey:         "",
		DockerVersion:  "1.5.0",
	}
	TestRole = &shipyard.Role{
		ID:   "0",
		Name: "testrole",
	}
	TestAccount = &shipyard.Account{
		ID:       "0",
		Username: "testuser",
		Password: "test",
		Role:     TestRole,
	}
	TestClusterInfo = &shipyard.ClusterInfo{
		Cpus:           1.0,
		Memory:         4.0,
		ContainerCount: 10,
		EngineCount:    0,
		ImageCount:     15,
		ReservedCpus:   0.0,
		ReservedMemory: 0.0,
		Version:        "test",
	}
	TestEvent = &shipyard.Event{
		Type:      "test-event",
		Container: TestContainerInfo,
		Message:   "test message",
		Tags:      []string{"test-tag"},
	}
	TestServiceKey = &shipyard.ServiceKey{
		Key:         "test-key",
		Description: "Test Key",
	}
	TestWebhookKey = &dockerhub.WebhookKey{
		ID:    "1234",
		Image: "ehazlett/test",
		Key:   "abcdefg",
	}
)

func getTestEngine(id string, addr string) *shipyard.Engine {
	return &shipyard.Engine{
		ID:             id,
		Addr:           addr,
		CACertificate:  "",
		SSLCertificate: "",
		SSLKey:         "",
		DockerVersion:  "1.5.0",
	}
}

func getTestEngines() []*shipyard.Engine {
	return []*shipyard.Engine{
		TestEngine,
	}
}

func getTestContainerInfo(id string, name string, image string) *dockerclient.ContainerInfo {
	return &dockerclient.ContainerInfo{
		Id:      id,
		Created: string(time.Now().UnixNano()),
		Name:    name,
		Image:   image,
	}
}

func getTestContainers() []*dockerclient.ContainerInfo {
	return []*dockerclient.ContainerInfo{
		getTestContainerInfo(TestContainerId, TestContainerName, TestContainerImage),
	}
}

func getTestEvents() []*shipyard.Event {
	return []*shipyard.Event{
		TestEvent,
	}
}
