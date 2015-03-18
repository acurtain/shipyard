package manager

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
	r "github.com/dancannon/gorethink"
	"github.com/gorilla/sessions"
	"github.com/samalba/dockerclient"
	"github.com/shipyard/shipyard"
	"github.com/shipyard/shipyard/dockerhub"
)

const (
	tblNameConfig      = "config"
	tblNameEvents      = "events"
	tblNameAccounts    = "accounts"
	tblNameRoles       = "roles"
	tblNameServiceKeys = "service_keys"
	tblNameWebhookKeys = "webhook_keys"
	storeKey           = "shipyard"
	trackerHost        = "http://tracker.shipyard-project.com"
	EngineHealthUp     = "up"
	EngineHealthDown   = "down"
)

var (
	ErrAccountExists          = errors.New("account already exists")
	ErrAccountDoesNotExist    = errors.New("account does not exist")
	ErrRoleDoesNotExist       = errors.New("role does not exist")
	ErrServiceKeyDoesNotExist = errors.New("service key does not exist")
	ErrInvalidAuthToken       = errors.New("invalid auth token")
	ErrExtensionDoesNotExist  = errors.New("extension does not exist")
	ErrWebhookKeyDoesNotExist = errors.New("webhook key does not exist")
	logger                    = logrus.New()
	store                     = sessions.NewCookieStore([]byte(storeKey))
)

type Manager interface {
	Account(username string) (*shipyard.Account, error)
	Accounts() ([]*shipyard.Account, error)
	AddEngine(engine *shipyard.Engine) error
	Authenticate(username, password string) bool
	ChangePassword(username, password string) error
	ClusterInfo() *shipyard.ClusterInfo
	Container(id string) (*dockerclient.ContainerInfo, error)
	Containers(all bool, size bool, filters string) ([]*dockerclient.ContainerInfo, error)
	ContainersByImage(name string, all bool) ([]*dockerclient.ContainerInfo, error)
	DeleteAccount(account *shipyard.Account) error
	DeleteRole(role *shipyard.Role) error
	DeleteWebhookKey(id string) error
	Destroy(id string) error
	Engines() []*shipyard.Engine
	Engine(id string) *shipyard.Engine
	Events(limit int) ([]*shipyard.Event, error)
	IdenticalContainers(container *dockerclient.ContainerInfo, all bool) ([]*dockerclient.ContainerInfo, error)
	Logs(container *dockerclient.ContainerInfo, stdout bool, stderr bool) (io.ReadCloser, error)
	NewAuthToken(username, userAgent string) (*shipyard.AuthToken, error)
	NewServiceKey(description string) (*shipyard.ServiceKey, error)
	NewWebhookKey(image string) (*dockerhub.WebhookKey, error)
	PurgeEvents() error
	RedeployContainers(image string) error
	RemoveEngine(id string) error
	RemoveServiceKey(key string) error
	Restart(id string, timeout int) error
	Role(name string) (*shipyard.Role, error)
	Roles() ([]*shipyard.Role, error)
	Run(config *dockerclient.ContainerConfig, count int, pull bool) ([]string, error)
	SaveAccount(account *shipyard.Account) error
	SaveRole(role *shipyard.Role) error
	SaveServiceKey(key *shipyard.ServiceKey) error
	SaveEngine(engine *shipyard.Engine) error
	SaveEvent(event *shipyard.Event) error
	SaveWebhookKey(key *dockerhub.WebhookKey) error
	Scale(container *dockerclient.ContainerInfo, count int) error
	ServiceKey(key string) (*shipyard.ServiceKey, error)
	ServiceKeys() ([]*shipyard.ServiceKey, error)
	Stop(id string, timeout int) error
	Store() *sessions.CookieStore
	StoreKey() string
	VerifyAuthToken(username, token string) error
	VerifyServiceKey(key string) error
	WebhookKey(key string) (*dockerhub.WebhookKey, error)
	WebhookKeys() ([]*dockerhub.WebhookKey, error)
}

type (
	DefaultManager struct {
		address          string
		database         string
		authKey          string
		session          *r.Session
		engines          []*shipyard.Engine
		authenticator    *shipyard.Authenticator
		store            *sessions.CookieStore
		version          string
		disableUsageInfo bool
		storeKey         string
		client           *dockerclient.DockerClient
	}
)

func NewManager(addr string, database string, authKey string, version string, disableUsageInfo bool, client *dockerclient.DockerClient) (Manager, error) {
	session, err := r.Connect(r.ConnectOpts{
		Address:  addr,
		Database: database,
		AuthKey:  authKey,
		MaxIdle:  10,
		Timeout:  time.Second * 30,
	})
	if err != nil {
		return nil, err
	}
	logger.Info("checking database")
	r.DbCreate(database).Run(session)
	m := DefaultManager{
		address:          addr,
		database:         database,
		authKey:          authKey,
		session:          session,
		authenticator:    &shipyard.Authenticator{},
		store:            store,
		storeKey:         storeKey,
		version:          version,
		disableUsageInfo: disableUsageInfo,
		client:           client,
	}
	m.initdb()
	m.init()
	return m, nil
}

func (m DefaultManager) Store() *sessions.CookieStore {
	return m.store
}

func (m DefaultManager) StoreKey() string {
	return m.storeKey
}

func (m DefaultManager) initdb() {
	// create tables if needed
	tables := []string{tblNameConfig, tblNameEvents, tblNameAccounts, tblNameRoles, tblNameServiceKeys, tblNameWebhookKeys}
	for _, tbl := range tables {
		_, err := r.Table(tbl).Run(m.session)
		if err != nil {
			if _, err := r.Db(m.database).TableCreate(tbl).Run(m.session); err != nil {
				logger.Fatalf("error creating table: %s", err)
			}
		}
	}
}

func (m DefaultManager) init() error {
	// anonymous usage info
	go m.usageReport()
	return nil
}

func (m DefaultManager) usageReport() {
	if m.disableUsageInfo {
		return
	}
	m.uploadUsage()
	t := time.NewTicker(1 * time.Hour).C
	for {
		select {
		case <-t:
			go m.uploadUsage()
		}
	}
}

func (m DefaultManager) uploadUsage() {
	id := "anon"
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Name != "lo" {
				hw := iface.HardwareAddr.String()
				id = strings.Replace(hw, ":", "", -1)
				break
			}
		}
	}
	info := m.ClusterInfo()
	usage := &shipyard.Usage{
		ID:              id,
		Version:         m.version,
		NumOfEngines:    info.EngineCount,
		NumOfImages:     info.ImageCount,
		NumOfContainers: info.ContainerCount,
		TotalCpus:       info.Cpus,
		TotalMemory:     info.Memory,
	}
	b, err := json.Marshal(usage)
	if err != nil {
		logger.Warnf("error serializing usage info: %s", err)
	}
	buf := bytes.NewBuffer(b)
	if _, err := http.Post(fmt.Sprintf("%s/update", trackerHost), "application/json", buf); err != nil {
		logger.Warnf("error sending usage info: %s", err)
	}
}

func (m DefaultManager) AddEngine(engine *shipyard.Engine) error {
	stat, err := engine.Ping()
	if err != nil {
		return err

	}
	if stat != 200 {
		err := fmt.Errorf("Received status code '%d' when contacting %s", stat, engine.Addr)
		return err

	}
	if _, err := r.Table(tblNameConfig).Insert(engine).RunWrite(m.session); err != nil {
		return err

	}
	m.init()
	evt := &shipyard.Event{
		Type:    "add-engine",
		Message: fmt.Sprintf("addr=%s", engine.Addr),
		Time:    time.Now(),
		Tags:    []string{"cluster"},
	}
	if err := m.SaveEvent(evt); err != nil {
		return err

	}
	return nil

}

func (m DefaultManager) SaveEngine(engine *shipyard.Engine) error {
	if _, err := r.Table(tblNameConfig).Replace(engine).RunWrite(m.session); err != nil {
		return err

	}
	return nil

}

func (m DefaultManager) RemoveEngine(id string) error {
	var engine *shipyard.Engine
	res, err := r.Table(tblNameConfig).Filter(map[string]string{"id": id}).Run(m.session)
	if err != nil {
		return err

	}
	if err := res.One(&engine); err != nil {
		if err == r.ErrEmptyResult {
			return nil

		}
		return err

	}
	evt := &shipyard.Event{
		Type:    "remove-engine",
		Message: fmt.Sprintf("addr=%s", engine.Addr),
		Time:    time.Now(),
		Tags:    []string{"cluster"},
	}
	if err := m.SaveEvent(evt); err != nil {
		return err

	}
	if _, err := r.Table(tblNameConfig).Get(id).Delete().RunWrite(m.session); err != nil {
		return err

	}
	m.init()
	return nil

}

func (m DefaultManager) Engines() []*shipyard.Engine {
	return m.engines
}

func (m DefaultManager) Engine(id string) *shipyard.Engine {
	for _, e := range m.engines {
		if e.ID == id {
			return e
		}
	}
	return nil
}

func (m DefaultManager) Container(id string) (*dockerclient.ContainerInfo, error) {
	containers, err := m.Containers(true, false, "")
	if err != nil {
		return nil, err
	}
	for _, cnt := range containers {
		if strings.HasPrefix(cnt.Id, id) {
			return cnt, nil
		}
	}
	return nil, nil
}

func (m DefaultManager) Logs(container *dockerclient.ContainerInfo, stdout bool, stderr bool) (io.ReadCloser, error) {
	data, err := m.Logs(container, stdout, stderr)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (m DefaultManager) Containers(all bool, size bool, filters string) ([]*dockerclient.ContainerInfo, error) {
	containers, err := m.client.ListContainers(all, size, filters)
	if err != nil {
		return nil, err
	}
	containerInfos := []*dockerclient.ContainerInfo{}
	for _, c := range containers {
		if info, _ := m.client.InspectContainer(c.Id); info != nil {
			containerInfos = append(containerInfos, info)
		}
	}
	return containerInfos, nil
}

func (m DefaultManager) ContainersByImage(name string, all bool) ([]*dockerclient.ContainerInfo, error) {
	allContainers, err := m.Containers(all, false, "")
	if err != nil {
		return nil, err
	}
	imageContainers := []*dockerclient.ContainerInfo{}
	for _, c := range allContainers {
		if strings.Index(c.Config.Image, name) > -1 {
			imageContainers = append(imageContainers, c)
		}
	}
	return imageContainers, nil
}

func (m DefaultManager) IdenticalContainers(container *dockerclient.ContainerInfo, all bool) ([]*dockerclient.ContainerInfo, error) {
	containers := []*dockerclient.ContainerInfo{}
	imageContainers, err := m.ContainersByImage(container.Config.Image, all)
	if err != nil {
		return nil, err
	}
	for _, c := range imageContainers {
		args := len(c.Args)
		origArgs := len(container.Args)
		if c.Config.Memory == container.Config.Memory && args == origArgs {
			containers = append(containers, c)
		}
	}
	return containers, nil
}

func (m DefaultManager) ClusterInfo() *shipyard.ClusterInfo {
	info := m.ClusterInfo()
	clusterInfo := &shipyard.ClusterInfo{
		Cpus:           info.Cpus,
		Memory:         info.Memory,
		ContainerCount: info.ContainerCount,
		EngineCount:    info.EngineCount,
		ImageCount:     info.ImageCount,
		ReservedCpus:   info.ReservedCpus,
		ReservedMemory: info.ReservedMemory,
		Version:        m.version,
	}
	return clusterInfo
}

func (m DefaultManager) Restart(id string, timeout int) error {
	return m.client.RestartContainer(id, timeout)
}

func (m DefaultManager) Stop(id string, timeout int) error {
	return m.client.StopContainer(id, timeout)
}

func (m DefaultManager) Destroy(id string) error {
	if err := m.client.KillContainer(id, "9"); err != nil {
		return err
	}
	if err := m.client.RemoveContainer(id, true, true); err != nil {
		return err
	}
	return nil
}

func (m DefaultManager) SaveServiceKey(key *shipyard.ServiceKey) error {
	if _, err := r.Table(tblNameServiceKeys).Insert(key).RunWrite(m.session); err != nil {
		return err
	}
	evt := &shipyard.Event{
		Type:    "add-service-key",
		Time:    time.Now(),
		Message: fmt.Sprintf("description=%s", key.Description),
		Tags:    []string{"cluster", "security"},
	}
	if err := m.SaveEvent(evt); err != nil {
		return err
	}
	return nil
}

func (m DefaultManager) RemoveServiceKey(key string) error {
	k, err := m.ServiceKey(key)
	if err != nil {
		return err
	}
	evt := &shipyard.Event{
		Type:    "remove-service-key",
		Time:    time.Now(),
		Message: fmt.Sprintf("description=%s", k.Description),
		Tags:    []string{"cluster", "security"},
	}
	if err := m.SaveEvent(evt); err != nil {
		return err
	}
	if _, err := r.Table(tblNameServiceKeys).Filter(map[string]string{"key": key}).Delete().RunWrite(m.session); err != nil {
		return err
	}
	return nil
}

func (m DefaultManager) SaveEvent(event *shipyard.Event) error {
	if _, err := r.Table(tblNameEvents).Insert(event).RunWrite(m.session); err != nil {
		return err
	}
	return nil
}

func (m DefaultManager) Events(limit int) ([]*shipyard.Event, error) {
	t := r.Table(tblNameEvents).OrderBy(r.Desc("Time"))
	if limit > -1 {
		t.Limit(limit)
	}
	res, err := t.Run(m.session)
	if err != nil {
		return nil, err
	}
	events := []*shipyard.Event{}
	if err := res.All(&events); err != nil {
		return nil, err
	}
	return events, nil
}

func (m DefaultManager) PurgeEvents() error {
	if _, err := r.Table(tblNameEvents).Delete().RunWrite(m.session); err != nil {
		return err
	}
	return nil
}

func (m DefaultManager) ServiceKey(key string) (*shipyard.ServiceKey, error) {
	res, err := r.Table(tblNameServiceKeys).Filter(map[string]string{"key": key}).Run(m.session)
	if err != nil {
		return nil, err

	}
	if res.IsNil() {
		return nil, ErrServiceKeyDoesNotExist
	}
	var k *shipyard.ServiceKey
	if err := res.One(&k); err != nil {
		return nil, err
	}
	return k, nil
}

func (m DefaultManager) ServiceKeys() ([]*shipyard.ServiceKey, error) {
	res, err := r.Table(tblNameServiceKeys).Run(m.session)
	if err != nil {
		return nil, err
	}
	keys := []*shipyard.ServiceKey{}
	if err := res.All(&keys); err != nil {
		return nil, err
	}
	return keys, nil
}

func (m DefaultManager) Accounts() ([]*shipyard.Account, error) {
	res, err := r.Table(tblNameAccounts).OrderBy(r.Asc("username")).Run(m.session)
	if err != nil {
		return nil, err
	}
	accounts := []*shipyard.Account{}
	if err := res.All(&accounts); err != nil {
		return nil, err
	}
	return accounts, nil
}

func (m DefaultManager) Account(username string) (*shipyard.Account, error) {
	res, err := r.Table(tblNameAccounts).Filter(map[string]string{"username": username}).Run(m.session)
	if err != nil {
		return nil, err

	}
	if res.IsNil() {
		return nil, ErrAccountDoesNotExist
	}
	var account *shipyard.Account
	if err := res.One(&account); err != nil {
		return nil, err
	}
	return account, nil
}

func (m DefaultManager) SaveAccount(account *shipyard.Account) error {
	pass := account.Password
	hash, err := m.authenticator.Hash(pass)
	if err != nil {
		return err
	}
	// check if exists; if so, update
	acct, err := m.Account(account.Username)
	if err != nil && err != ErrAccountDoesNotExist {
		return err
	}
	account.Password = hash
	if acct != nil {
		if _, err := r.Table(tblNameAccounts).Filter(map[string]string{"username": account.Username}).Update(map[string]string{"password": hash}).RunWrite(m.session); err != nil {
			return err
		}
		return nil
	}
	if _, err := r.Table(tblNameAccounts).Insert(account).RunWrite(m.session); err != nil {
		return err
	}
	evt := &shipyard.Event{
		Type:    "add-account",
		Time:    time.Now(),
		Message: fmt.Sprintf("username=%s", account.Username),
		Tags:    []string{"cluster", "security"},
	}
	if err := m.SaveEvent(evt); err != nil {
		return err
	}
	return nil
}

func (m DefaultManager) DeleteAccount(account *shipyard.Account) error {
	res, err := r.Table(tblNameAccounts).Filter(map[string]string{"id": account.ID}).Delete().Run(m.session)
	if err != nil {
		return err
	}
	if res.IsNil() {
		return ErrAccountDoesNotExist
	}
	evt := &shipyard.Event{
		Type:    "delete-account",
		Time:    time.Now(),
		Message: fmt.Sprintf("username=%s", account.Username),
		Tags:    []string{"cluster", "security"},
	}
	if err := m.SaveEvent(evt); err != nil {
		return err
	}
	return nil
}

func (m DefaultManager) Roles() ([]*shipyard.Role, error) {
	res, err := r.Table(tblNameRoles).OrderBy(r.Asc("name")).Run(m.session)
	if err != nil {
		return nil, err
	}
	roles := []*shipyard.Role{}
	if err := res.All(&roles); err != nil {
		return nil, err
	}
	return roles, nil
}

func (m DefaultManager) Role(name string) (*shipyard.Role, error) {
	res, err := r.Table(tblNameRoles).Filter(map[string]string{"name": name}).Run(m.session)
	if err != nil {
		return nil, err

	}
	if res.IsNil() {
		return nil, ErrRoleDoesNotExist
	}
	var role *shipyard.Role
	if err := res.One(&role); err != nil {
		return nil, err
	}
	return role, nil
}

func (m DefaultManager) SaveRole(role *shipyard.Role) error {
	if _, err := r.Table(tblNameRoles).Insert(role).RunWrite(m.session); err != nil {
		return err
	}
	evt := &shipyard.Event{
		Type:    "add-role",
		Time:    time.Now(),
		Message: fmt.Sprintf("name=%s", role.Name),
		Tags:    []string{"cluster", "security"},
	}
	if err := m.SaveEvent(evt); err != nil {
		return err
	}
	return nil
}

func (m DefaultManager) DeleteRole(role *shipyard.Role) error {
	res, err := r.Table(tblNameRoles).Get(role.ID).Delete().Run(m.session)
	if err != nil {
		return err
	}
	if res.IsNil() {
		return ErrRoleDoesNotExist
	}
	evt := &shipyard.Event{
		Type:    "delete-role",
		Time:    time.Now(),
		Message: fmt.Sprintf("name=%s", role.Name),
		Tags:    []string{"cluster", "security"},
	}
	if err := m.SaveEvent(evt); err != nil {
		return err
	}
	return nil
}

func (m DefaultManager) Authenticate(username, password string) bool {
	acct, err := m.Account(username)
	if err != nil {
		logger.Error(err)
		return false
	}
	return m.authenticator.Authenticate(password, acct.Password)
}

func (m DefaultManager) NewAuthToken(username string, userAgent string) (*shipyard.AuthToken, error) {
	tk, err := m.authenticator.GenerateToken()
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	acct, err := m.Account(username)
	if err != nil {
		return nil, err
	}
	token := &shipyard.AuthToken{}
	tokens := acct.Tokens
	found := false
	for _, t := range tokens {
		if t.UserAgent == userAgent {
			found = true
			t.Token = tk
			token = t
			break
		}
	}
	if !found {
		token = &shipyard.AuthToken{
			UserAgent: userAgent,
			Token:     tk,
		}
		tokens = append(tokens, token)
	}
	// delete token
	if _, err := r.Table(tblNameAccounts).Filter(map[string]string{"username": username}).Filter(r.Row.Field("user_agent").Eq(userAgent)).Delete().Run(m.session); err != nil {
		return nil, err
	}
	// add
	if _, err := r.Table(tblNameAccounts).Filter(map[string]string{"username": username}).Update(map[string]interface{}{"tokens": tokens}).RunWrite(m.session); err != nil {
		return nil, err
	}
	return token, nil
}

func (m DefaultManager) VerifyAuthToken(username, token string) error {
	acct, err := m.Account(username)
	if err != nil {
		return err
	}
	found := false
	for _, t := range acct.Tokens {
		if token == t.Token {
			found = true
			break
		}
	}
	if !found {
		return ErrInvalidAuthToken
	}
	return nil
}

func (m DefaultManager) VerifyServiceKey(key string) error {
	if _, err := m.ServiceKey(key); err != nil {
		return err
	}
	return nil
}

func (m DefaultManager) NewServiceKey(description string) (*shipyard.ServiceKey, error) {
	k, err := m.authenticator.GenerateToken()
	if err != nil {
		return nil, err
	}
	key := &shipyard.ServiceKey{
		Key:         k[24:],
		Description: description,
	}
	if err := m.SaveServiceKey(key); err != nil {
		return nil, err
	}
	return key, nil
}

func (m DefaultManager) ChangePassword(username, password string) error {
	hash, err := m.authenticator.Hash(password)
	if err != nil {
		return err
	}
	if _, err := r.Table(tblNameAccounts).Filter(map[string]string{"username": username}).Update(map[string]string{"password": hash}).Run(m.session); err != nil {
		return err
	}
	return nil
}

func (m DefaultManager) RedeployContainers(image string) error {
	containers, err := m.Containers(false, false, "")
	if err != nil {
		return err
	}

	deployed := false
	for _, c := range containers {
		if strings.Index(c.Config.Image, image) > -1 {
			cfg := c.Config
			logger.Infof("pulling latest image for %s", image)
			// TODO: add AuthConfig for PullImage
			if err := m.client.PullImage(image, nil); err != nil {
				return err
			}
			m.Destroy(c.Id)
			// in order to keep fast deploys, we must deploy
			// to the same host that the image was running on previously
			lbl := fmt.Sprintf("constraint:node==%s", c.Node.Name)
			cfg.Env = []string{lbl}

			cId, err := m.client.CreateContainer(cfg, "")
			if err != nil {
				return err
			}

			if err := m.client.StartContainer(cId, &c.Config.HostConfig); err != nil {
				return err
			}
			deployed = true
			logger.Infof("deployed updated container %s via webhook for %s", cId, image)
		}
	}
	if deployed {
		evt := &shipyard.Event{
			Type:    "deploy",
			Message: fmt.Sprintf("%s deployed", image),
			Time:    time.Now(),
			Tags:    []string{"deploy"},
		}
		if err := m.SaveEvent(evt); err != nil {
			return err
		}
	}
	return nil
}

func (m DefaultManager) WebhookKeys() ([]*dockerhub.WebhookKey, error) {
	res, err := r.Table(tblNameWebhookKeys).OrderBy(r.Asc("image")).Run(m.session)
	if err != nil {
		return nil, err
	}
	keys := []*dockerhub.WebhookKey{}
	if err := res.All(&keys); err != nil {
		return nil, err
	}
	return keys, nil
}

func (m DefaultManager) NewWebhookKey(image string) (*dockerhub.WebhookKey, error) {
	k := generateId(16)
	key := &dockerhub.WebhookKey{
		Key:   k,
		Image: image,
	}
	if err := m.SaveWebhookKey(key); err != nil {
		return nil, err
	}
	return key, nil
}

func (m DefaultManager) WebhookKey(key string) (*dockerhub.WebhookKey, error) {
	res, err := r.Table(tblNameWebhookKeys).Filter(map[string]string{"key": key}).Run(m.session)
	if err != nil {
		return nil, err

	}
	if res.IsNil() {
		return nil, ErrWebhookKeyDoesNotExist
	}
	var k *dockerhub.WebhookKey
	if err := res.One(&k); err != nil {
		return nil, err
	}
	return k, nil
}

func (m DefaultManager) SaveWebhookKey(key *dockerhub.WebhookKey) error {
	if _, err := r.Table(tblNameWebhookKeys).Insert(key).RunWrite(m.session); err != nil {
		return err
	}
	evt := &shipyard.Event{
		Type:    "add-webhook-key",
		Time:    time.Now(),
		Message: fmt.Sprintf("image=%s", key.Image),
		Tags:    []string{"docker", "webhook"},
	}
	if err := m.SaveEvent(evt); err != nil {
		return err
	}
	return nil
}

func (m DefaultManager) DeleteWebhookKey(id string) error {
	key, err := m.WebhookKey(id)
	if err != nil {
		return err
	}
	res, err := r.Table(tblNameWebhookKeys).Get(key.ID).Delete().Run(m.session)
	if err != nil {
		return err
	}
	if res.IsNil() {
		return ErrWebhookKeyDoesNotExist
	}
	evt := &shipyard.Event{
		Type:    "delete-webhook-key",
		Time:    time.Now(),
		Message: fmt.Sprintf("image=%s key=%s", key.Image, key.Key),
		Tags:    []string{"docker", "webhook"},
	}
	if err := m.SaveEvent(evt); err != nil {
		return err
	}
	return nil
}

func (m DefaultManager) Run(config *dockerclient.ContainerConfig, count int, pull bool) ([]string, error) {
	launched := []string{}

	// TODO: convert to use channel
	var wg sync.WaitGroup
	wg.Add(count)
	var runErr error
	for i := 0; i < count; i++ {
		go func(wg *sync.WaitGroup) {
			cId, err := m.client.CreateContainer(config, "")
			if err != nil {
				runErr = err
			}
			if err := m.client.StartContainer(cId, &config.HostConfig); err != nil {
				runErr = err
			}
			launched = append(launched, cId)
			wg.Done()
		}(&wg)
	}
	wg.Wait()
	return launched, runErr
}

func (m DefaultManager) Scale(container *dockerclient.ContainerInfo, count int) error {
	imageContainers, err := m.IdenticalContainers(container, true)
	if err != nil {
		return err
	}
	containerCount := len(imageContainers)
	// check which way we need to scale
	if containerCount > count { // down
		numKill := containerCount - count
		delContainers := imageContainers[0:numKill]
		for _, c := range delContainers {
			if err := m.Destroy(c.Id); err != nil {
				return err
			}
		}
	} else if containerCount < count { // up
		numAdd := count - containerCount
		// check for vols or links -- if so, launch on same engine
		if len(container.Volumes) > 0 || len(container.Config.HostConfig.Links) > 0 {
			eng := container.Node
			t := fmt.Sprintf("constraint:node==%s", eng.Name)
			env := container.Config.Env
			env = append(env, t)
			container.Config.Env = env
		}
		if _, err := m.Run(container.Config, numAdd, false); err != nil {
			return err
		}
	} else { // none
		logger.Info("no need to scale")
	}
	return nil
}
