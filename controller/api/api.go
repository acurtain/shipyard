package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/codegangsta/negroni"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/samalba/dockerclient"
	"github.com/shipyard/shipyard"
	"github.com/shipyard/shipyard/controller/manager"
	"github.com/shipyard/shipyard/controller/middleware/access"
	"github.com/shipyard/shipyard/controller/middleware/auth"
	"github.com/shipyard/shipyard/dockerhub"
)

type (
	Api struct {
		listenAddr string
		manager    manager.Manager
	}

	Credentials struct {
		Username string `json:"username,omitempty"`
		Password string `json:"password,omitempty"`
	}
)

func NewApi(listenAddr string, manager manager.Manager) (*Api, error) {
	return &Api{
		listenAddr: listenAddr,
		manager:    manager,
	}, nil
}

func (a *Api) destroy(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	if err := a.manager.Destroy(id); err != nil {
		log.Errorf("error destroying %s: %s", id, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Infof("destroyed container %s", id)

	w.WriteHeader(http.StatusNoContent)
}

func (a *Api) run(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	p := r.FormValue("pull")
	c := r.FormValue("count")
	count := 1
	pull := false
	if p != "" {
		pv, err := strconv.ParseBool(p)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		pull = pv
	}
	if c != "" {
		cc, err := strconv.Atoi(c)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		count = cc
	}
	var config *dockerclient.ContainerConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		log.Warnf("error decoding image: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	launched, err := a.manager.Run(config, count, pull)
	if err != nil {
		log.Warnf("error running container: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusCreated)

	if err := json.NewEncoder(w).Encode(launched); err != nil {
		log.Error(err)
	}
}

func (a *Api) stopContainer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	if err := a.manager.Stop(id, 10); err != nil {
		log.Errorf("error stopping %s: %s", id, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Infof("stopped container %s", id)

	w.WriteHeader(http.StatusNoContent)
}

func (a *Api) containerLogs(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	container, err := a.manager.Container(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if container == nil {
		http.Error(w, "container not found", http.StatusNotFound)
		return
	}

	data, err := a.manager.Logs(container, true, true)
	if err != nil {
		log.Errorf("error getting logs for %s: %s", container.Id, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	stdcopy.StdCopy(w, w, data)
}

func (a *Api) restartContainer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	if err := a.manager.Restart(id, 10); err != nil {
		log.Errorf("error restarting %s: %s", id, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Infof("restarted container %s", id)

	w.WriteHeader(http.StatusNoContent)
}

func (a *Api) scaleContainer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	r.ParseForm()
	sCount := r.FormValue("count")
	if sCount == "" {
		http.Error(w, "you must specify a count", http.StatusBadRequest)
		return
	}
	count, err := strconv.Atoi(sCount)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	container, err := a.manager.Container(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if container == nil {
		http.Error(w, "container not found", http.StatusNotFound)
		return
	}

	if err := a.manager.Scale(container, count); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Infof("scaled container %s (%s) to %d", id, container.Config.Image, count)

	w.WriteHeader(http.StatusNoContent)
}

func (a *Api) engines(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	engines := a.manager.Engines()
	if err := json.NewEncoder(w).Encode(engines); err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
}

func (a *Api) inspectEngine(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	vars := mux.Vars(r)
	id := vars["id"]
	engine := a.manager.Engine(id)
	if err := json.NewEncoder(w).Encode(engine); err != nil {
		log.Error(err)
	}
}

func (a *Api) containers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	containers, err := a.manager.Containers(true, false, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(containers); err != nil {
		log.Error(err)
	}
}

func (a *Api) inspectContainer(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	vars := mux.Vars(r)
	id := vars["id"]
	container, err := a.manager.Container(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if container == nil {
		http.Error(w, "container not found", http.StatusNotFound)
		return
	}
	if err := json.NewEncoder(w).Encode(container); err != nil {
		log.Error(err)
	}
	fmt.Println(container)
}

func (a *Api) addEngine(w http.ResponseWriter, r *http.Request) {
	var engine *shipyard.Engine
	if err := json.NewDecoder(r.Body).Decode(&engine); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	health := &shipyard.Health{
		Status:       "pending",
		ResponseTime: 0,
	}
	engine.Health = health
	if err := a.manager.AddEngine(engine); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Infof("added engine id=%s addr=%s", engine.ID, engine.Addr)
	w.WriteHeader(http.StatusCreated)
}

func (a *Api) removeEngine(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	engine := a.manager.Engine(id)
	if err := a.manager.RemoveEngine(engine.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Infof("removed engine id=%s addr=%s", engine.ID, engine.Addr)
	w.WriteHeader(http.StatusNoContent)
}

func (a *Api) clusterInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	info := a.manager.ClusterInfo()
	if err := json.NewEncoder(w).Encode(info); err != nil {
		log.Error(err)
	}
}

func (a *Api) addServiceKey(w http.ResponseWriter, r *http.Request) {
	var k *shipyard.ServiceKey
	if err := json.NewDecoder(r.Body).Decode(&k); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	key, err := a.manager.NewServiceKey(k.Description)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Infof("created service key key=%s description=%s", key.Key, key.Description)
	if err := json.NewEncoder(w).Encode(key); err != nil {
		log.Error(err)
	}
}

func (a *Api) serviceKeys(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	keys, err := a.manager.ServiceKeys()
	if err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := json.NewEncoder(w).Encode(keys); err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
}

func (a *Api) removeServiceKey(w http.ResponseWriter, r *http.Request) {
	var key *shipyard.ServiceKey
	if err := json.NewDecoder(r.Body).Decode(&key); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := a.manager.RemoveServiceKey(key.Key); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Infof("removed service key %s", key.Key)
	w.WriteHeader(http.StatusNoContent)
}

func (a *Api) events(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	limit := -1
	l := r.FormValue("limit")
	if l != "" {
		lt, err := strconv.Atoi(l)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		limit = lt
	}
	events, err := a.manager.Events(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(events); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *Api) purgeEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	if err := a.manager.PurgeEvents(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Info("cluster events purged")
	w.WriteHeader(http.StatusNoContent)
}

func (a *Api) accounts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	accounts, err := a.manager.Accounts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(accounts); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *Api) addAccount(w http.ResponseWriter, r *http.Request) {
	var account *shipyard.Account
	if err := json.NewDecoder(r.Body).Decode(&account); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := a.manager.SaveAccount(account); err != nil {
		log.Errorf("error saving account: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Infof("saved account %s", account.Username)
	w.WriteHeader(http.StatusNoContent)
}

func (a *Api) deleteAccount(w http.ResponseWriter, r *http.Request) {
	var acct *shipyard.Account
	if err := json.NewDecoder(r.Body).Decode(&acct); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	account, err := a.manager.Account(acct.Username)
	if err != nil {
		log.Errorf("error deleting account: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := a.manager.DeleteAccount(account); err != nil {
		log.Errorf("error deleting account: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Infof("deleted account %s (%s)", account.Username, account.ID)
	w.WriteHeader(http.StatusNoContent)
}

func (a *Api) roles(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	roles, err := a.manager.Roles()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(roles); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *Api) role(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	vars := mux.Vars(r)
	name := vars["name"]
	role, err := a.manager.Role(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(role); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *Api) addRole(w http.ResponseWriter, r *http.Request) {
	var role *shipyard.Role
	if err := json.NewDecoder(r.Body).Decode(&role); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := a.manager.SaveRole(role); err != nil {
		log.Errorf("error saving role: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Infof("saved role %s", role.Name)
	w.WriteHeader(http.StatusNoContent)
}

func (a *Api) deleteRole(w http.ResponseWriter, r *http.Request) {
	var role *shipyard.Role
	if err := json.NewDecoder(r.Body).Decode(&role); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := a.manager.DeleteRole(role); err != nil {
		log.Errorf("error deleting role: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *Api) webhookKeys(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	keys, err := a.manager.WebhookKeys()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(keys); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *Api) webhookKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")

	vars := mux.Vars(r)
	id := vars["id"]
	key, err := a.manager.WebhookKey(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(key); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *Api) addWebhookKey(w http.ResponseWriter, r *http.Request) {
	var k *dockerhub.WebhookKey
	if err := json.NewDecoder(r.Body).Decode(&k); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	key, err := a.manager.NewWebhookKey(k.Image)
	if err != nil {
		log.Errorf("error generating webhook key: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Infof("saved webhook key image=%s", key.Image)
	if err := json.NewEncoder(w).Encode(key); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *Api) deleteWebhookKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	if err := a.manager.DeleteWebhookKey(id); err != nil {
		log.Errorf("error deleting webhook key: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Infof("removed webhook key id=%s", id)
	w.WriteHeader(http.StatusNoContent)
}

func (a *Api) login(w http.ResponseWriter, r *http.Request) {
	var creds *Credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !a.manager.Authenticate(creds.Username, creds.Password) {
		log.Errorf("invalid login for %s from %s", creds.Username, r.RemoteAddr)
		http.Error(w, "invalid username/password", http.StatusForbidden)
		return
	}
	// return token
	token, err := a.manager.NewAuthToken(creds.Username, r.UserAgent())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(token); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *Api) changePassword(w http.ResponseWriter, r *http.Request) {
	session, _ := a.manager.Store().Get(r, a.manager.StoreKey())
	var creds *Credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	username := session.Values["username"].(string)
	if username == "" {
		http.Error(w, "unauthorized", http.StatusInternalServerError)
		return
	}
	if err := a.manager.ChangePassword(username, creds.Password); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *Api) hubWebhook(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	key, err := a.manager.WebhookKey(id)
	if err != nil {
		log.Errorf("invalid webook key: id=%s from %s", id, r.RemoteAddr)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	var webhook *dockerhub.Webhook
	if err := json.NewDecoder(r.Body).Decode(&webhook); err != nil {
		log.Errorf("error parsing webhook: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if strings.Index(webhook.Repository.RepoName, key.Image) == -1 {
		log.Errorf("webhook key image does not match: repo=%s image=%s", webhook.Repository.RepoName, key.Image)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	log.Infof("received webhook notification for %s", webhook.Repository.RepoName)
	if err := a.manager.RedeployContainers(webhook.Repository.RepoName); err != nil {
		log.Errorf("error redeploying containers: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *Api) Run() error {
	globalMux := http.NewServeMux()

	apiRouter := mux.NewRouter()
	apiRouter.HandleFunc("/api/accounts", a.accounts).Methods("GET")
	apiRouter.HandleFunc("/api/accounts", a.addAccount).Methods("POST")
	apiRouter.HandleFunc("/api/accounts", a.deleteAccount).Methods("DELETE")
	apiRouter.HandleFunc("/api/roles", a.roles).Methods("GET")
	apiRouter.HandleFunc("/api/roles/{name}", a.role).Methods("GET")
	apiRouter.HandleFunc("/api/roles", a.addRole).Methods("POST")
	apiRouter.HandleFunc("/api/roles", a.deleteRole).Methods("DELETE")
	apiRouter.HandleFunc("/api/cluster/info", a.clusterInfo).Methods("GET")
	apiRouter.HandleFunc("/api/containers", a.containers).Methods("GET")
	apiRouter.HandleFunc("/api/containers", a.run).Methods("POST")
	apiRouter.HandleFunc("/api/containers/{id}", a.inspectContainer).Methods("GET")
	apiRouter.HandleFunc("/api/containers/{id}", a.destroy).Methods("DELETE")
	apiRouter.HandleFunc("/api/containers/{id}/stop", a.stopContainer).Methods("GET")
	apiRouter.HandleFunc("/api/containers/{id}/restart", a.restartContainer).Methods("GET")
	apiRouter.HandleFunc("/api/containers/{id}/scale", a.scaleContainer).Methods("GET")
	apiRouter.HandleFunc("/api/containers/{id}/logs", a.containerLogs).Methods("GET")
	apiRouter.HandleFunc("/api/events", a.events).Methods("GET")
	apiRouter.HandleFunc("/api/events", a.purgeEvents).Methods("DELETE")
	apiRouter.HandleFunc("/api/engines", a.engines).Methods("GET")
	apiRouter.HandleFunc("/api/engines", a.addEngine).Methods("POST")
	apiRouter.HandleFunc("/api/engines/{id}", a.inspectEngine).Methods("GET")
	apiRouter.HandleFunc("/api/engines/{id}", a.removeEngine).Methods("DELETE")
	apiRouter.HandleFunc("/api/servicekeys", a.serviceKeys).Methods("GET")
	apiRouter.HandleFunc("/api/servicekeys", a.addServiceKey).Methods("POST")
	apiRouter.HandleFunc("/api/servicekeys", a.removeServiceKey).Methods("DELETE")
	apiRouter.HandleFunc("/api/webhookkeys", a.webhookKeys).Methods("GET")
	apiRouter.HandleFunc("/api/webhookkeys/{id}", a.webhookKey).Methods("GET")
	apiRouter.HandleFunc("/api/webhookkeys", a.addWebhookKey).Methods("POST")
	apiRouter.HandleFunc("/api/webhookkeys/{id}", a.deleteWebhookKey).Methods("DELETE")

	// global handler
	globalMux.Handle("/", http.FileServer(http.Dir("static")))

	// api router; protected by auth
	apiAuthRouter := negroni.New()
	apiAuthRequired := auth.NewAuthRequired(a.manager)
	apiAccessRequired := access.NewAccessRequired(a.manager)
	apiAuthRouter.Use(negroni.HandlerFunc(apiAuthRequired.HandlerFuncWithNext))
	apiAuthRouter.Use(negroni.HandlerFunc(apiAccessRequired.HandlerFuncWithNext))
	apiAuthRouter.UseHandler(apiRouter)
	globalMux.Handle("/api/", apiAuthRouter)

	// account router ; protected by auth
	accountRouter := mux.NewRouter()
	accountRouter.HandleFunc("/account/changepassword", a.changePassword).Methods("POST")
	accountAuthRouter := negroni.New()
	accountAuthRequired := auth.NewAuthRequired(a.manager)
	accountAuthRouter.Use(negroni.HandlerFunc(accountAuthRequired.HandlerFuncWithNext))
	accountAuthRouter.UseHandler(accountRouter)
	globalMux.Handle("/account/", accountAuthRouter)

	// login handler; public
	loginRouter := mux.NewRouter()
	loginRouter.HandleFunc("/auth/login", a.login).Methods("POST")
	globalMux.Handle("/auth/", loginRouter)

	// hub handler; public
	hubRouter := mux.NewRouter()
	hubRouter.HandleFunc("/hub/webhook/{id}", a.hubWebhook).Methods("POST")
	globalMux.Handle("/hub/", hubRouter)

	// check for admin user
	if _, err := a.manager.Account("admin"); err == manager.ErrAccountDoesNotExist {
		// create roles
		r := &shipyard.Role{
			Name: "admin",
		}
		ru := &shipyard.Role{
			Name: "user",
		}
		if err := a.manager.SaveRole(r); err != nil {
			log.Fatal(err)
		}
		if err := a.manager.SaveRole(ru); err != nil {
			log.Fatal(err)
		}
		role, err := a.manager.Role(r.Name)
		if err != nil {
			log.Fatal(err)
		}
		acct := &shipyard.Account{
			Username: "admin",
			Password: "shipyard",
			Role:     role,
		}
		if err := a.manager.SaveAccount(acct); err != nil {
			log.Fatal(err)
		}
		log.Infof("created admin user: username: admin password: shipyard")
	}

	log.Infof("controller listening on %s", a.listenAddr)

	return http.ListenAndServe(a.listenAddr, context.ClearHandler(globalMux))
}
