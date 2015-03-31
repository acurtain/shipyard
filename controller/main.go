package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/samalba/dockerclient"
	"github.com/shipyard/shipyard"
	"github.com/shipyard/shipyard/controller/api"
	"github.com/shipyard/shipyard/controller/manager"
	"github.com/shipyard/shipyard/controller/utils"
)

var (
	listenAddr        string
	dockerUrl         string
	rethinkdbAddr     string
	rethinkdbDatabase string
	rethinkdbAuthKey  string
	tlsCaCert         string
	tlsCert           string
	tlsKey            string
	tlsAllowInsecure  bool
	disableUsageInfo  bool
	showVersion       bool
	controllerManager manager.Manager
)

const (
	STORE_KEY = "shipyard"
	VERSION   = shipyard.VERSION
)

func init() {
	flag.StringVar(&listenAddr, "listen", ":8080", "listen address")
	flag.StringVar(&dockerUrl, "docker", "tcp://127.0.0.1:2375", "docker url")
	flag.StringVar(&tlsCaCert, "tls-ca-cert", "", "TLS CA certificate")
	flag.StringVar(&tlsCert, "tls-cert", "", "TLS Certificate")
	flag.StringVar(&tlsKey, "tls-key", "", "TLS Key")
	flag.BoolVar(&tlsAllowInsecure, "tls-allow-insecure", false, "TLS allow insecure CA")
	flag.StringVar(&rethinkdbAddr, "rethinkdb-addr", "127.0.0.1:28015", "rethinkdb address")
	flag.StringVar(&rethinkdbDatabase, "rethinkdb-database", "shipyard", "rethinkdb database")
	flag.StringVar(&rethinkdbAuthKey, "rethinkdb-auth-key", "", "rethinkdb auth key")
	flag.BoolVar(&disableUsageInfo, "disable-usage-info", false, "disable anonymous usage info")
	flag.BoolVar(&showVersion, "version", false, "show version and exit")
}

func main() {
	rHost := os.Getenv("RETHINKDB_PORT_28015_TCP_ADDR")
	rPort := os.Getenv("RETHINKDB_PORT_28015_TCP_PORT")
	rDb := os.Getenv("RETHINKDB_DATABASE")
	rAuthKey := os.Getenv("RETHINKDB_AUTH_KEY")
	if rHost != "" && rPort != "" {
		rethinkdbAddr = fmt.Sprintf("%s:%s", rHost, rPort)
	}
	if rDb != "" {
		rethinkdbDatabase = rDb
	}
	if rAuthKey != "" {
		rethinkdbAuthKey = rAuthKey
	}
	flag.Parse()
	if showVersion {
		fmt.Println(VERSION)
		os.Exit(0)
	}

	log.Infof("shipyard version %s", VERSION)

	var tlsConfig *tls.Config
	if tlsCaCert != "" && tlsCert != "" && tlsKey != "" {
		log.Println("using tls for communication with swarm")
		caCert, err := ioutil.ReadFile(tlsCaCert)
		if err != nil {
			log.Fatalf("error loading tls ca cert: %s", err)
		}

		cert, err := ioutil.ReadFile(tlsCert)
		if err != nil {
			log.Fatalf("error loading tls cert: %s", err)
		}

		key, err := ioutil.ReadFile(tlsKey)
		if err != nil {
			log.Fatalf("error loading tls key: %s", err)
		}

		cfg, err := utils.GetTLSConfig(caCert, cert, key, tlsAllowInsecure)
		if err != nil {
			log.Fatalf("error configuring tls: %s", err)
		}
		tlsConfig = cfg
	}

	client, err := dockerclient.NewDockerClient(dockerUrl, tlsConfig)
	if err != nil {
		log.Fatal(err)
	}

	controllerManager, err = manager.NewManager(rethinkdbAddr, rethinkdbDatabase, rethinkdbAuthKey, VERSION, disableUsageInfo, client)
	if err != nil {
		log.Fatal(err)
	}

	shipyardApi, err := api.NewApi(listenAddr, controllerManager)
	if err != nil {
		log.Fatal(err)
	}

	if err := shipyardApi.Run(); err != nil {
		log.Fatal(err)
	}
}
