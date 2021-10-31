package sshlib

import (
	"io/ioutil"
	"net"
	"os/user"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

type SshConfig struct {
	User         string
	IdentityFile string
}

var sshconfig = make(map[string]*ssh.ClientConfig)

func init() {
	sshconfig = loadConfig()
}

func loadConfig() map[string]*ssh.ClientConfig {
	m := make(map[string]*ssh.ClientConfig)
	me, err := user.Current()
	if err != nil {
		me, _ = user.LookupId("0")
	}
	path := filepath.Join(me.HomeDir, ".ssh/config")
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return m
	}
	var hosts []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if strings.HasPrefix(line, "Host ") {
			hosts = strings.Fields(line)[1:]
			for _, h := range hosts {
				m[h] = &ssh.ClientConfig{
					Auth: []ssh.AuthMethod{},
					HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
						return nil
					},
				}
			}
		}
		if strings.HasPrefix(line, "User ") {
			u := strings.Fields(line)[1]
			for _, h := range hosts {
				m[h].User = u
			}
		}
		if strings.HasPrefix(line, "IdentityFile ") {
			p := strings.Fields(line)[1]
			p = strings.ReplaceAll(p, "~", me.HomeDir)
			for _, h := range hosts {
				k := new(keychain)
				err := k.loadPEM(p)
				if err != nil {
					continue
				}
				for _, v := range k.keys {
					m[h].Auth = append(m[h].Auth, ssh.PublicKeys(v))
				}
			}
		}
	}
	return m
}

func hostConfig(host ...string) *ssh.ClientConfig {
	for _, v := range host {
		if val, ok := sshconfig[v]; ok {
			return val
		}
	}
	if val, ok := sshconfig["*"]; ok {
		return val
	}
	return nil
}
