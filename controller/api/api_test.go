package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	log "github.com/Sirupsen/logrus"
	"github.com/samalba/dockerclient"
	"github.com/shipyard/shipyard"
	"github.com/shipyard/shipyard/controller/mock_test"
	"github.com/shipyard/shipyard/dockerhub"
	"github.com/stretchr/testify/assert"
)

func getTestApi() (*Api, error) {
	log.SetLevel(log.ErrorLevel)
	m := mock_test.MockManager{}
	return NewApi("", m)
}

func TestApiGetAccounts(t *testing.T) {
	api, err := getTestApi()
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(api.accounts))
	defer ts.Close()

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, res.StatusCode, 200, "expected response code 200")
	accts := []*shipyard.Account{}
	if err := json.NewDecoder(res.Body).Decode(&accts); err != nil {
		t.Fatal(err)
	}

	assert.NotEqual(t, len(accts), 0, "expected accounts; received none")

	acct := accts[0]

	assert.Equal(t, acct.ID, mock_test.TestAccount.ID, fmt.Sprintf("expected ID %s; got %s", mock_test.TestAccount.ID, acct.ID))
}

func TestApiPostAccounts(t *testing.T) {
	api, err := getTestApi()
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(api.addAccount))
	defer ts.Close()

	data := []byte(`{"username": "testuser", "password": "foo"}`)

	res, err := http.Post(ts.URL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, res.StatusCode, 204, "expected response code 204")
}

func TestApiDeleteAccount(t *testing.T) {
	api, err := getTestApi()
	if err != nil {
		t.Fatal(err)
	}

	transport := &http.Transport{}
	client := &http.Client{Transport: transport}

	ts := httptest.NewServer(http.HandlerFunc(api.addAccount))
	defer ts.Close()

	data := []byte(`{"username": "testuser", "password": "foo"}`)

	req, err := http.NewRequest("DELETE", ts.URL, bytes.NewBuffer(data))
	if err != nil {
		t.Fatal(err)
	}

	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, res.StatusCode, 204, "expected response code 204")
}

func TestApiGetRoles(t *testing.T) {
	api, err := getTestApi()
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(api.roles))
	defer ts.Close()

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, res.StatusCode, 200, "expected response code 200")
	roles := []*shipyard.Role{}
	if err := json.NewDecoder(res.Body).Decode(&roles); err != nil {
		t.Fatal(err)
	}

	assert.NotEqual(t, len(roles), 0, "expected roles; received none")

	role := roles[0]

	assert.Equal(t, role.ID, mock_test.TestRole.ID, fmt.Sprintf("expected ID %s; got %s", mock_test.TestRole.ID, role.ID))
}

func TestApiGetRole(t *testing.T) {
	api, err := getTestApi()
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(api.role))
	defer ts.Close()

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, res.StatusCode, 200, "expected response code 200")
	role := &shipyard.Role{}
	if err := json.NewDecoder(res.Body).Decode(&role); err != nil {
		t.Fatal(err)
	}

	assert.NotEqual(t, role.ID, nil, "expected role; received nil")

	assert.Equal(t, role.ID, mock_test.TestRole.ID, fmt.Sprintf("expected ID %s; got %s", mock_test.TestRole.ID, role.ID))
}

func TestApiPostRoles(t *testing.T) {
	api, err := getTestApi()
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(api.addRole))
	defer ts.Close()

	data := []byte(`{"name": "testrole"}`)

	res, err := http.Post(ts.URL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, res.StatusCode, 204, "expected response code 204")
}

func TestApiDeleteRole(t *testing.T) {
	api, err := getTestApi()
	if err != nil {
		t.Fatal(err)
	}

	transport := &http.Transport{}
	client := &http.Client{Transport: transport}

	ts := httptest.NewServer(http.HandlerFunc(api.addAccount))
	defer ts.Close()

	data := []byte(`{"name": "testrole"}`)

	req, err := http.NewRequest("DELETE", ts.URL, bytes.NewBuffer(data))
	if err != nil {
		t.Fatal(err)
	}

	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, res.StatusCode, 204, "expected response code 204")
}

func TestApiGetClusterInfo(t *testing.T) {
	api, err := getTestApi()
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(api.clusterInfo))
	defer ts.Close()

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, res.StatusCode, 200, "expected response code 200")
	info := &shipyard.ClusterInfo{}
	if err := json.NewDecoder(res.Body).Decode(&info); err != nil {
		t.Fatal(err)
	}

	assert.NotEqual(t, info.Version, nil, "expected info; received nil")

	assert.Equal(t, info.Cpus, mock_test.TestClusterInfo.Cpus, fmt.Sprintf("expected %.2f cpus; got %s", mock_test.TestClusterInfo.Cpus, info.Cpus))
	assert.Equal(t, info.Memory, mock_test.TestClusterInfo.Memory, fmt.Sprintf("expected %.2f memory; got %s", mock_test.TestClusterInfo.Memory, info.Memory))
	assert.Equal(t, info.ImageCount, mock_test.TestClusterInfo.ImageCount, fmt.Sprintf("expected %d images; got %s", mock_test.TestClusterInfo.ImageCount, info.ImageCount))
}

func TestApiGetContainers(t *testing.T) {
	api, err := getTestApi()
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(api.containers))
	defer ts.Close()

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, res.StatusCode, 200, "expected response code 200")
	containers := []*dockerclient.ContainerInfo{}

	if err := json.NewDecoder(res.Body).Decode(&containers); err != nil {
		t.Fatal(err)
	}

	assert.NotEqual(t, len(containers), 0, "expected containers; received none")
}

func TestApiPostContainers(t *testing.T) {
	api, err := getTestApi()
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(api.containers))
	defer ts.Close()

	data := []byte(`{"image": "testuser"}`)

	res, err := http.Post(ts.URL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, res.StatusCode, 200, "expected response code 200")
}

func TestApiGetContainer(t *testing.T) {
	api, err := getTestApi()
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(api.inspectContainer))
	defer ts.Close()

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, res.StatusCode, 200, "expected response code 200")

	cInfo := &dockerclient.ContainerInfo{}

	if err := json.NewDecoder(res.Body).Decode(&cInfo); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, cInfo.Id, mock_test.TestContainerId, "expected id %s; received %s", mock_test.TestContainerId, cInfo.Id)
}

func TestApiDestroyContainer(t *testing.T) {
	api, err := getTestApi()
	if err != nil {
		t.Fatal(err)
	}

	transport := &http.Transport{}
	client := &http.Client{Transport: transport}

	ts := httptest.NewServer(http.HandlerFunc(api.destroy))
	defer ts.Close()

	data := []byte(`{"id": "12345"}`)

	req, err := http.NewRequest("DELETE", ts.URL, bytes.NewBuffer(data))
	if err != nil {
		t.Fatal(err)
	}

	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, res.StatusCode, 204, "expected response code 204")
}

func TestApiStopContainer(t *testing.T) {
	api, err := getTestApi()
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(api.stopContainer))
	defer ts.Close()

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, res.StatusCode, 204, "expected response code 204")
}

func TestApiRestartContainer(t *testing.T) {
	api, err := getTestApi()
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(api.restartContainer))
	defer ts.Close()

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, res.StatusCode, 204, "expected response code 204")
}

func TestApiScaleContainer(t *testing.T) {
	t.Skipf("skipping; TODO: mock a.manager.Container(id)")
	api, err := getTestApi()
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(api.scaleContainer))
	defer ts.Close()

	res, err := http.Get(ts.URL + "/" + mock_test.TestContainerId + "?count=1")
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, res.StatusCode, 204, "expected response code 204")
}

func TestApiContainerLogs(t *testing.T) {
	t.Skipf("skipping; TODO: mock a.manager.Container(id)")
	api, err := getTestApi()
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(api.containerLogs))
	defer ts.Close()

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, res.StatusCode, 200, "expected response code 200")
}

func TestApiGetEvents(t *testing.T) {
	api, err := getTestApi()
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(api.events))
	defer ts.Close()

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, res.StatusCode, 200, "expected response code 200")
	events := []*shipyard.Event{}

	if err := json.NewDecoder(res.Body).Decode(&events); err != nil {
		t.Fatal(err)
	}

	assert.NotEqual(t, len(events), 0, "expected events; received none")
}

func TestApiPurgeEvents(t *testing.T) {
	api, err := getTestApi()
	if err != nil {
		t.Fatal(err)
	}

	transport := &http.Transport{}
	client := &http.Client{Transport: transport}

	ts := httptest.NewServer(http.HandlerFunc(api.purgeEvents))
	defer ts.Close()

	req, err := http.NewRequest("DELETE", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, res.StatusCode, 204, "expected response code 204")
}

func TestApiGetEngines(t *testing.T) {
	api, err := getTestApi()
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(api.engines))
	defer ts.Close()

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, res.StatusCode, 200, "expected response code 200")
	engines := []*shipyard.Engine{}

	if err := json.NewDecoder(res.Body).Decode(&engines); err != nil {
		t.Fatal(err)
	}

	assert.NotEqual(t, len(engines), 0, "expected engines; received none")
}

func TestApiPostEngines(t *testing.T) {
	api, err := getTestApi()
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(api.addEngine))
	defer ts.Close()

	data := []byte(`{"addr": "127.0.0.1:1234", "name": "foo-engine"}`)

	res, err := http.Post(ts.URL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, res.StatusCode, 201, "expected response code 201")
}

func TestApiGetEngine(t *testing.T) {
	api, err := getTestApi()
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(api.inspectEngine))
	defer ts.Close()

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, res.StatusCode, 200, "expected response code 200")
	engine := &shipyard.Engine{}
	if err := json.NewDecoder(res.Body).Decode(&engine); err != nil {
		t.Fatal(err)
	}

	assert.NotEqual(t, engine.ID, nil, "expected engine; received nil")

	assert.Equal(t, engine.ID, mock_test.TestEngine.ID, fmt.Sprintf("expected ID %s; got %s", mock_test.TestEngine.ID, engine.ID))
}

func TestApiRemoveEngine(t *testing.T) {
	api, err := getTestApi()
	if err != nil {
		t.Fatal(err)
	}

	transport := &http.Transport{}
	client := &http.Client{Transport: transport}

	ts := httptest.NewServer(http.HandlerFunc(api.removeEngine))
	defer ts.Close()

	req, err := http.NewRequest("DELETE", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, res.StatusCode, 204, "expected response code 204")
}

func TestApiGetSerivceKeys(t *testing.T) {
	api, err := getTestApi()
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(api.serviceKeys))
	defer ts.Close()

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, res.StatusCode, 200, "expected response code 200")
	keys := []*shipyard.ServiceKey{}

	if err := json.NewDecoder(res.Body).Decode(&keys); err != nil {
		t.Fatal(err)
	}

	assert.NotEqual(t, len(keys), 0, "expected keys; received none")
}

func TestApiRemoveServiceKey(t *testing.T) {
	api, err := getTestApi()
	if err != nil {
		t.Fatal(err)
	}

	transport := &http.Transport{}
	client := &http.Client{Transport: transport}

	ts := httptest.NewServer(http.HandlerFunc(api.removeServiceKey))
	defer ts.Close()

	data := []byte(`{"key": "test-key"}`)

	req, err := http.NewRequest("DELETE", ts.URL, bytes.NewBuffer(data))
	if err != nil {
		t.Fatal(err)
	}

	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, res.StatusCode, 204, "expected response code 204")
}

func TestApiGetWebhookKeys(t *testing.T) {
	api, err := getTestApi()
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(api.webhookKeys))
	defer ts.Close()

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, res.StatusCode, 200, "expected response code 200")
	keys := []*dockerhub.WebhookKey{}

	if err := json.NewDecoder(res.Body).Decode(&keys); err != nil {
		t.Fatal(err)
	}

	assert.NotEqual(t, len(keys), 0, "expected keys; received none")

	key := "abcdefg"

	assert.Equal(t, keys[0].Key, key, "expected key %s; received %s", key, keys[0].Key)
}
