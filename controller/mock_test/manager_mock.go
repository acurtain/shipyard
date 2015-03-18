package mock_test

import (
	"fmt"
	"io"

	"github.com/gorilla/sessions"
	"github.com/samalba/dockerclient"
	"github.com/shipyard/shipyard"
	"github.com/shipyard/shipyard/dockerhub"
)

type MockManager struct{}

func (m MockManager) AddEngine(engine *shipyard.Engine) error {
	return nil
}

func (m MockManager) SaveEngine(engine *shipyard.Engine) error {
	return nil
}

func (m MockManager) RemoveEngine(id string) error {
	return nil
}

func (m MockManager) Engines() []*shipyard.Engine {
	return getTestEngines()
}

func (m MockManager) Engine(id string) *shipyard.Engine {
	return TestEngine
}

func (m MockManager) Container(id string) (*dockerclient.ContainerInfo, error) {
	return getTestContainerInfo(TestContainerId, TestContainerName, TestContainerImage), nil
}

func (m MockManager) Logs(container *dockerclient.ContainerInfo, stdout, stderr bool) (io.ReadCloser, error) {
	return nil, nil
}

func (m MockManager) Containers(all bool, size bool, filters string) ([]*dockerclient.ContainerInfo, error) {
	return getTestContainers(), nil
}

func (m MockManager) ContainersByImage(name string, all bool) ([]*dockerclient.ContainerInfo, error) {
	return nil, nil
}

func (m MockManager) IdenticalContainers(container *dockerclient.ContainerInfo, all bool) ([]*dockerclient.ContainerInfo, error) {
	return nil, nil
}

func (m MockManager) ClusterInfo() *shipyard.ClusterInfo {
	return TestClusterInfo
}

func (m MockManager) Stop(id string, timeout int) error {
	return nil
}

func (m MockManager) Restart(id string, timeout int) error {
	return nil
}

func (m MockManager) Destroy(id string) error {
	return nil
}

func (m MockManager) SaveServiceKey(key *shipyard.ServiceKey) error {
	return nil
}

func (m MockManager) RemoveServiceKey(key string) error {
	return nil
}

func (m MockManager) SaveEvent(event *shipyard.Event) error {
	return nil
}

func (m MockManager) Events(limit int) ([]*shipyard.Event, error) {
	return getTestEvents(), nil
}

func (m MockManager) PurgeEvents() error {
	return nil
}

func (m MockManager) ServiceKey(key string) (*shipyard.ServiceKey, error) {
	return nil, nil
}

func (m MockManager) ServiceKeys() ([]*shipyard.ServiceKey, error) {
	return nil, nil
}

func (m MockManager) Accounts() ([]*shipyard.Account, error) {
	return []*shipyard.Account{
		TestAccount,
	}, nil
}

func (m MockManager) Account(username string) (*shipyard.Account, error) {
	return nil, nil
}

func (m MockManager) SaveAccount(account *shipyard.Account) error {
	return nil
}

func (m MockManager) DeleteAccount(account *shipyard.Account) error {
	return nil
}

func (m MockManager) Roles() ([]*shipyard.Role, error) {
	return []*shipyard.Role{
		TestRole,
	}, nil
}

func (m MockManager) Role(name string) (*shipyard.Role, error) {
	return &shipyard.Role{
		ID:   "0",
		Name: name,
	}, nil
}

func (m MockManager) SaveRole(role *shipyard.Role) error {
	return nil
}

func (m MockManager) DeleteRole(role *shipyard.Role) error {
	return nil
}

func (m MockManager) Authenticate(username, password string) bool {
	return false
}

func (m MockManager) NewAuthToken(username, userAgent string) (*shipyard.AuthToken, error) {
	return nil, nil
}

func (m MockManager) VerifyAuthToken(username, token string) error {
	return nil
}

func (m MockManager) VerifyServiceKey(key string) error {
	return nil
}

func (m MockManager) NewServiceKey(description string) (*shipyard.ServiceKey, error) {
	return nil, nil
}

func (m MockManager) ChangePassword(username, password string) error {
	return nil
}

func (m MockManager) Extensions() ([]*shipyard.Extension, error) {
	return nil, nil
}

func (m MockManager) Extension(id string) (*shipyard.Extension, error) {
	return nil, nil
}

func (m MockManager) SaveExtension(ext *shipyard.Extension) error {
	return nil
}

func (m MockManager) RegisterExtension(ext *shipyard.Extension) error {
	return nil
}

func (m MockManager) UnregisterExtension(ext *shipyard.Extension) error {
	return nil
}

func (m MockManager) DeleteExtension(id string) error {
	return nil
}

func (m MockManager) RedeployContainers(image string) error {
	return nil
}

func (m MockManager) WebhookKeys() ([]*dockerhub.WebhookKey, error) {
	return nil, nil
}

func (m MockManager) NewWebhookKey(image string) (*dockerhub.WebhookKey, error) {
	return nil, nil
}

func (m MockManager) WebhookKey(key string) (*dockerhub.WebhookKey, error) {
	return nil, nil
}

func (m MockManager) SaveWebhookKey(key *dockerhub.WebhookKey) error {
	return nil
}

func (m MockManager) DeleteWebhookKey(id string) error {
	return nil
}

func (m MockManager) Run(config *dockerclient.ContainerConfig, count int, pull bool) ([]string, error) {
	ids := []string{"12345"}
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	return ids, nil
}

func (m MockManager) Scale(container *dockerclient.ContainerInfo, count int) error {
	if container == nil {
		return fmt.Errorf("container cannot be nil")
	}
	return nil
}

func (m MockManager) Store() *sessions.CookieStore {
	return nil
}

func (m MockManager) StoreKey() string {
	return ""
}
