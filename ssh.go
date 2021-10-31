package sshlib

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type Provider interface {
	Hosts() []*Host
}

type Host struct {
	sync.Mutex
	Id              int
	Hostname        string
	ManageIp        string
	Mrtg            string
	Port            uint
	session         *ssh.Session
	Err             chan error
	StdIn           chan string
	StdOut          chan string
	StdErr          chan string
	Running         chan bool
	Stopped         chan bool
	LastResult      string
	Buckets         []*Bucket
	Timeout         time.Duration
	DialTimeout     time.Duration
	FirstCmdTimeout time.Duration
	manager         *SshManager
}

func (h *Host) clientConfig() *ssh.ClientConfig {
	c := hostConfig(h.Hostname, h.ManageIp)
	if c == nil {
		return h.manager.clientConfig
	}
	return c
}

type Bucket struct {
	Cmd string
	Res string
}

type SshManager struct {
	sync.Mutex
	User         string
	Key          string
	Sudo         bool
	Password     []string
	sudoPassword string
	Workers      int
	InitCmd      string
	clientConfig *ssh.ClientConfig
	agent        net.Conn
	HostMap      map[string]*Host
	Sig          chan os.Signal
	Log          *log.Logger
	hostIndex    int
}

func NewSshManager() *SshManager {
	return &SshManager{
		InitCmd: "/bin/bash",
		Log:     log.New(os.Stderr, "[sshlib] ", log.LstdFlags|log.Lshortfile),
	}
}

func (m *SshManager) SetSudoPassword(p string) {
	m.sudoPassword = p
}

func strip(v string) string {
	return strings.TrimSpace(strings.Trim(v, "\n"))
}

type keychain struct {
	keys []ssh.Signer
}

func (k *keychain) Key(i int) (ssh.PublicKey, error) {
	if i < 0 || i >= len(k.keys) {
		return nil, nil
	}
	return k.keys[i].PublicKey(), nil
}

func (k *keychain) add(key ssh.Signer) {
	k.keys = append(k.keys, key)
}

func (k *keychain) loadPEM(file string) error {
	buf, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	key, err := ssh.ParsePrivateKey(buf)
	if err != nil {
		return err
	}
	k.add(key)
	return nil
}

func (manager *SshManager) init() {
	manager.clientConfig = &ssh.ClientConfig{
		User: manager.User,
		Auth: []ssh.AuthMethod{},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}
	if conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		manager.agent = conn
		Logger.Notice("use SSH_AUTH_SOCK")
		manager.clientConfig.Auth = append(manager.clientConfig.Auth, ssh.PublicKeysCallback(agent.NewClient(conn).Signers))
	} else {
		k := new(keychain)
		// Add path to id_rsa file
		err := k.loadPEM(manager.Key)

		if err == nil {
			for _, v := range k.keys {
				Logger.Notice("use key", v)
				manager.clientConfig.Auth = append(manager.clientConfig.Auth, ssh.PublicKeys(v))
			}
		} else {
			Logger.Notice("use key failed", err)
		}
	}

	for k, v := range manager.Password {
		Logger.Notice("use password", k)
		manager.clientConfig.Auth = append(manager.clientConfig.Auth, ssh.Password(v))
	}

	manager.HostMap = make(map[string]*Host)

}

func (manager *SshManager) Close() {
	if manager.agent != nil {
		manager.agent.Close()
	}
	for _, h := range manager.HostMap {
		if h.session != nil {
			h.session.Close()
		}
	}
}

type tmpClient struct {
	client *ssh.Client
	err    error
}

// setup host
func (manager *SshManager) Process(host *Host) *Host {
	Logger.Noticef("[%s] received host", host.Hostname)
	if val, ok := manager.HostMap[host.Hostname]; ok {
		Logger.Noticef("[%s] received host exist from cache", host)
		return val
	}

	host.manager = manager

	host.StdIn = make(chan string)
	host.StdOut = make(chan string)
	host.StdErr = make(chan string)
	host.Running = make(chan bool)
	host.Stopped = make(chan bool)

	if host.Port == 0 {
		host.Port = 22
	}
	if host.Timeout == 0 {
		host.Timeout = 1 * time.Second
	}
	if host.DialTimeout == 0 {
		host.DialTimeout = 20 * time.Second
	}
	if host.FirstCmdTimeout == 0 {
		host.FirstCmdTimeout = 5 * time.Second
	}
	if host.Id == 0 {
		manager.hostIndex++
		host.Id = manager.hostIndex
	}

	Logger.Noticef("[%s] dial port %d start", host.Hostname, host.Port)

	client := make(chan *tmpClient)
	t1 := time.Now()
	go func() {
		c, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", host.ManageIp, host.Port), host.clientConfig())
		if err != nil {
			// 			panic(err)
			client <- &tmpClient{err: err}
			Logger.Errorf("[%s] dial port %d end with error %s", host.Hostname, host.Port, err.Error())
		} else {
			client <- &tmpClient{client: c}
			Logger.Noticef("[%s] dial port %d success %v", host.Hostname, host.Port, time.Since(t1))
		}
	}()
	select {
	case <-time.After(host.DialTimeout):
		Logger.Errorf("[%s] dial timeout %v", host.Hostname, host.DialTimeout)
		host.Err <- errors.New(fmt.Sprintf("[%s] dial timeout %v", host.Hostname, host.DialTimeout))
		return host
	case v := <-client:
		if v.err != nil {
			host.Err <- v.err
			return host
		}
		cli := v.client
		var err error
		Logger.Noticef("[%s] create session start", host.Hostname)
		host.session, err = cli.NewSession()
		if err != nil {
			host.Err <- err
			return host
		}

		modes := ssh.TerminalModes{
			ssh.ECHO:          0,     // disable echoing
			ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
			ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
		}

		if err := host.session.RequestPty("xterm", 160, 80, modes); err != nil {
			Logger.Errorf("%v", err.Error)
		} else {
			Logger.Noticef("[%s] xterm setup success", host.Hostname)
		}

		if err := host.muxShell(); err != nil {
			Logger.Errorf("%v", err.Error)
		} else {
			Logger.Noticef("[%s] redirect set success", host.Hostname)
		}

		if err := host.session.Start(manager.InitCmd); err != nil {
			Logger.Errorf("%v", err.Error())
		} else {
			Logger.Noticef("[%s] session start success", host.Hostname)
		}

	}

	manager.Lock()
	defer manager.Unlock()
	manager.HostMap[host.Hostname] = host
	Logger.Noticef("[%s] added to cache", host.Hostname)
	return host

}

func (host *Host) muxShell() error {
	sin, err := host.session.StdinPipe()
	if err != nil {
		return err
	}
	sout, err := host.session.StdoutPipe()
	if err != nil {
		return err
	}
	serr, err := host.session.StderrPipe()
	if err != nil {
		return err
	}
	go func() {
		Logger.Noticef("[%s] stdin redirect ready", host.Hostname)
		for {
			select {
			case cmd := <-host.StdIn:
				host.Running <- true
				host.Buckets = append(host.Buckets, &Bucket{Cmd: cmd})
				Logger.Noticef("[%s] send command: %s", host.Hostname, cmd)
				if host.manager.Sudo {
					cmd = "echo '" + host.manager.sudoPassword + "' | sudo -S " + cmd
				}
				sin.Write([]byte(cmd + "\n"))
			}
		}
	}()
	go func() {
		Logger.Noticef("[%s] stdout redirect ready", host.Hostname)

		scanner := bufio.NewScanner(sout)
		scanner.Buffer(make([]byte, 1024), 2*bufio.MaxScanTokenSize)
		for scanner.Scan() {
			host.StdOut <- scanner.Text()
		}
		if scanner.Err() != nil {
			host.StdOut <- scanner.Err().Error()
		}
	}()
	go func() {
		Logger.Noticef("[%s] stderr redirect ready", host.Hostname)
		scanner := bufio.NewScanner(serr)
		scanner.Buffer(make([]byte, 1024), 2*bufio.MaxScanTokenSize)
		for scanner.Scan() {
			host.StdErr <- scanner.Text()
		}
		if scanner.Err() != nil {
			host.StdErr <- scanner.Err().Error()
		}
	}()
	Logger.Noticef("[%s] start listening", host.Hostname)
	return nil
}
