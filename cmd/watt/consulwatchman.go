package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	consulapi "github.com/hashicorp/consul/api"

	"github.com/datawire/ambassador/pkg/consulwatch"
	"github.com/datawire/ambassador/pkg/supervisor"
	"github.com/datawire/ambassador/pkg/watt"
)

const (
	distLockKey = "AMB_CONSUL_CONNECT_LEADER"
)

const (
	// envAmbassadorID creates a secret for a specific instance of an Ambassador API Gateway. The TLS secret name will
	// be formatted as "$AMBASSADOR_ID-consul-connect."
	envAmbassadorID = "_AMBASSADOR_ID"

	// envSecretName is the full name of the Kubernetes Secret that contains the TLS certificate provided
	// by Consul. If this value is set then the value of AMBASSADOR_ID is ignored when the name of the TLS secret is
	// computed.
	envSecretName = "_AMBASSADOR_TLS_SECRET_NAME"

	// envSecretNamespace sets the namespace where the TLS secret is created.
	envSecretNamespace = "_AMBASSADOR_TLS_SECRET_NAMESPACE"
)

const (
	secretTemplate = `---
kind: Secret
apiVersion: v1
metadata:
    name: "%s"
type: "kubernetes.io/tls"
data:
    tls.crt: "%s"
    tls.key: "%s"
`
)

var logger *log.Logger

func init() {
	logger = log.New(os.Stdout, "", log.LstdFlags)
}

type agent struct {
	// AmbassadorID is the ID of the Ambassador instance.
	AmbassadorID string

	// The Agent registers a Consul Service when it starts and then fetches the leaf TLS certificate from the Consul
	// HTTP API with this name.
	ConsulServiceName string

	// SecretNamespace is the Namespace where the TLS secret is managed.
	SecretNamespace string

	// SecretName is the Name of the TLS secret managed by this agent.
	SecretName string

	// consulAPI is the client used to communicate with the Consul HTTP API server.
	consul *consulapi.Client
}

func newAgent(ambassadorID string, secretNamespace string, secretName string, consul *consulapi.Client) *agent {
	consulServiceName := "ambassador"
	if ambassadorID != "" {
		consulServiceName += "-" + ambassadorID
	}

	if secretName == "" {
		secretName = consulServiceName + "-consul-connect"
	}

	return &agent{
		AmbassadorID:      consulServiceName,
		SecretNamespace:   secretNamespace,
		SecretName:        secretName,
		ConsulServiceName: consulServiceName,
		consul:            consul,
	}
}

type consulEvent struct {
	WatchId   string
	Endpoints consulwatch.Endpoints
}

type consulwatchman struct {
	WatchMaker IConsulWatchMaker
	watchesCh  <-chan []ConsulWatchSpec
	watched    map[string]*supervisor.Worker
}

type ConsulWatchMaker struct {
	aggregatorCh chan<- consulEvent
}

// consulConnectWatcher is a watcher for Consul Connect certificates
type consulConnectWatcher struct {
	p      *supervisor.Process
	agent  *agent
	consul *consulapi.Client

	consulWorker *supervisor.Worker

	caRootWorker       *supervisor.Worker
	caRootCertificates chan *consulwatch.CARoots
	caRootWatcher      *consulwatch.ConnectCARootsWatcher

	leafCertificates chan *consulwatch.Certificate
	leafWatcher      *consulwatch.ConnectLeafWatcher
	leafWorker       *supervisor.Worker
}

func newConsulConnectWatcher(p *supervisor.Process, consul *consulapi.Client) *consulConnectWatcher {
	// TODO(alvaro): this shold be obtained from a custom resource
	agent := newAgent(os.Getenv(envAmbassadorID), os.Getenv(envSecretNamespace), os.Getenv(envSecretName), consul)

	return &consulConnectWatcher{
		p:                  p,
		consul:             consul,
		agent:              agent,
		caRootCertificates: make(chan *consulwatch.CARoots),
		leafCertificates:   make(chan *consulwatch.Certificate),
	}
}

// Watch retrieves the TLS certificate issued by the Consul CA and stores it as a Kubernetes
// secret that Ambassador will use to authenticate with upstream services.
func (w *consulConnectWatcher) Watch() error {
	var err error

	log.Printf("Watching Root CA for %s\n", w.agent.ConsulServiceName)
	w.caRootWatcher, err = consulwatch.NewConnectCARootsWatcher(w.consul, logger)
	if err != nil {
		return err
	}
	w.caRootWatcher.Watch(func(roots *consulwatch.CARoots, e error) {
		if e != nil {
			w.p.Logf("Error watching root CA: %v\n", err)
		}

		w.caRootCertificates <- roots
	})

	log.Printf("Watching CA leaf for %s\n", w.agent.ConsulServiceName)
	w.leafWatcher, err = consulwatch.NewConnectLeafWatcher(w.consul, logger, w.agent.ConsulServiceName)
	if err != nil {
		return err
	}
	w.leafWatcher.Watch(func(certificate *consulwatch.Certificate, e error) {
		if e != nil {
			w.p.Logf("Error watching certificates: %v\n", err)
		}
		w.leafCertificates <- certificate
	})

	w.consulWorker = w.p.Go(func(p *supervisor.Process) error {
		p.Logf("Starting Consul certificates watcher...")
		var caRoot *consulwatch.CARoot
		var leafCert *consulwatch.Certificate

		// wait for root CA and certificates, and update the
		// copy in Kubernetes when we get a new version
		for {
			select {
			case cert, ok := <-w.caRootCertificates:
				if !ok {
					return nil // return when one of the input channels is closed
				}
				temp := cert.Roots[cert.ActiveRootID]
				caRoot = &temp
			case cert, ok := <-w.leafCertificates:
				if !ok {
					return nil
				}
				leafCert = cert
			case <-p.Shutdown():
				return nil
			}

			if caRoot != nil && leafCert != nil {
				chain := createCertificateChain(caRoot.PEM, leafCert.PEM)
				secret := formatKubernetesSecretYAML(w.agent.SecretName, chain, leafCert.PrivateKeyPEM)

				p.Logf("Updating TLS certificate secret: namespace=%s, secret=%s", w.agent.SecretNamespace, w.agent.SecretName)
				if err := applySecret(w.agent.SecretNamespace, secret); err != nil {
					p.Log(err)
					continue
				}
			}
		}
	})
	w.leafWorker = w.p.Go(func(p *supervisor.Process) error {
		p.Log("Starting Consul leaf certificates watcher...")
		if err := w.leafWatcher.Start(); err != nil {
			p.Logf("failed to start Consul leaf watcher %v", err)
			return err
		}
		return nil
	})
	w.caRootWorker = w.p.Go(func(p *supervisor.Process) error {
		p.Log("Starting Consul CA certificate watcher...")
		if err := w.caRootWatcher.Start(); err != nil {
			p.Logf("failed to start Consul CA certificate watcher %v", err)
			return err
		}
		return nil
	})

	return nil
}

// Close stops watching Consul certificates
func (w *consulConnectWatcher) Close() {
	w.p.Logf("Stopping Consul Connect watchers...")
	w.caRootWatcher.Stop()
	w.caRootWorker.Wait()

	w.leafWatcher.Stop()
	w.leafWorker.Wait()

	w.caRootWatcher.Stop()
	close(w.caRootCertificates)

	w.leafWatcher.Stop()
	close(w.leafCertificates)

	w.consulWorker.Wait()
}

// MakeConsulWatch watches Consul and sends events to the aggregator channel
func (m *ConsulWatchMaker) MakeConsulWatch(spec ConsulWatchSpec) (*supervisor.Worker, error) {
	consulConfig := consulapi.DefaultConfig()
	consulConfig.Address = spec.ConsulAddress
	consulConfig.Datacenter = spec.Datacenter

	// TODO: Should we really allocated a Consul client per Service watch? Not sure... there some design stuff here
	// May be multiple consul clusters
	// May be different connection parameters on the consulConfig
	// Seems excessive...
	consul, err := consulapi.NewClient(consulConfig)
	if err != nil {
		return nil, err
	}

	worker := &supervisor.Worker{
		Name: fmt.Sprintf("consul:%s", spec.WatchId()),
		Work: func(p *supervisor.Process) error {
			eventsWatcher, err := consulwatch.New(consul, logger, spec.Datacenter, spec.ServiceName, true)
			if err != nil {
				p.Logf("failed to setup new consul watch %v", err)
				return err
			}

			eventsWatcher.Watch(func(endpoints consulwatch.Endpoints, e error) {
				endpoints.Id = spec.Id
				m.aggregatorCh <- consulEvent{spec.WatchId(), endpoints}
			})
			_ = p.Go(func(p *supervisor.Process) error {
				if err := eventsWatcher.Start(); err != nil {
					p.Logf("failed to start service watcher %v", err)
					return err
				}
				return nil
			})

			p.Logf("Creating distributed lock for Consul watchers.")
			distLock, err := watt.NewDistLock(consul, distLockKey, 15*time.Second)
			if err != nil {
				p.Logf("failed to setup distributed lock for Consul %v", err)
				return err
			}
			defer func(){
				p.Log("Releasing distributed lock...")
				if err = distLock.DestroySession(); err != nil {
					p.Logf("failed to release lock %v", err)
				}
			}()

			var cc *consulConnectWatcher = nil
			acquireCh := make(chan bool)
			releaseCh := make(chan bool)
			for {
				// loop is to re-attempt for lock acquisition when
				// the lock was initially acquired but auto released after some time
				go distLock.RetryLockAcquire(acquireCh, releaseCh)

				p.Logf("Waiting to acquire Consul lock...")
				select {
				case <-acquireCh:
					p.Logf("Acquired Consul lock: we are the leaders watching Consul certificates")
					cc = newConsulConnectWatcher(p, consul)
					if err := cc.Watch(); err != nil {
						return err
					}

				case <-p.Shutdown():
					p.Logf("Supervisor is shutting down...")
					cc.Close()
					return nil // we are done in the Worker: get out...
				}

				<-releaseCh
				p.Logf("Lost Consul lock: releasing watches and resources")
				cc.Close()
				// we will iterate and try to acquire the lock again...
			}
		},
		Retry: true,
	}

	return worker, nil
}

func (w *consulwatchman) Work(p *supervisor.Process) error {
	p.Ready()
	for {
		select {
		case watches := <-w.watchesCh:
			found := make(map[string]*supervisor.Worker)
			p.Logf("processing %d consul watches", len(watches))
			for _, cw := range watches {
				worker, err := w.WatchMaker.MakeConsulWatch(cw)
				if err != nil {
					p.Logf("failed to create consul watch %v", err)
					continue
				}

				if _, exists := w.watched[worker.Name]; exists {
					found[worker.Name] = w.watched[worker.Name]
				} else {
					p.Logf("add consul watcher %s\n", worker.Name)
					p.Supervisor().Supervise(worker)
					w.watched[worker.Name] = worker
					found[worker.Name] = worker
				}
			}

			// purge the watches that no longer are needed because they did not come through the in the latest
			// report
			for workerName, worker := range w.watched {
				if _, exists := found[workerName]; !exists {
					p.Logf("remove consul watcher %s\n", workerName)
					worker.Shutdown()
					worker.Wait()
				}
			}

			w.watched = found
		case <-p.Shutdown():
			p.Logf("shutdown initiated")
			return nil
		}
	}
}

func createCertificateChain(rootPEM string, leafPEM string) string {
	return leafPEM + rootPEM
}

func formatKubernetesSecretYAML(name string, chain string, key string) string {
	chain64 := base64.StdEncoding.EncodeToString([]byte(chain))
	key64 := base64.StdEncoding.EncodeToString([]byte(key))

	return fmt.Sprintf(secretTemplate, name, chain64, key64)
}

// applySecret creates/updates a secret with the help of `kubectl`
// TODO(alvaro): replace by a proper k8s API call
func applySecret(namespace string, yaml string) error {
	kubectl, err := exec.LookPath("kubectl")
	if err != nil {
		return err
	}

	args := []string{"apply", "-f", "-"}

	if namespace != "" {
		args = append(args, "--namespace", namespace)
	}

	cmd := exec.Command(kubectl, args...)

	var errBuffer bytes.Buffer
	cmd.Stderr = &errBuffer

	cmd.Stdin = bytes.NewBuffer([]byte(yaml))
	_, err = cmd.Output()
	fmt.Println(errBuffer.String())

	return err
}
