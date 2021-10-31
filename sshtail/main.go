package main

import (
	"bufio"
	"crypto/md5"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/aybabtme/rgbterm"
	"github.com/kiyor/sshlib"
)

var (
	verbose, version, sudo bool
	cmd, initCmd           string
	skip                   int
	flagUser               string
	dialtimeout            time.Duration
	flagKey                string

	Logger = sshlib.NewLogger(&sshlib.LogOptions{
		Name:      "ssh",
		ShowDebug: verbose,
		ShowErr:   true,
		ShowColor: true,
	})
)

func currentUser() *user.User {
	u, err := user.Current()
	if err != nil {
		u, _ = user.LookupId("0")
	}
	return u
}

func init() {
	flag.BoolVar(&verbose, "v", false, "verbose")
	flag.BoolVar(&version, "version", false, "output version")
	flag.BoolVar(&sudo, "sudo", false, "sudo")
	flag.StringVar(&flagKey, "i", "~/.ssh/id_rsa", "")
	flag.IntVar(&skip, "skip", 0, "skip line of output")
	flag.StringVar(&cmd, "c", "hostname", "command")
	flag.StringVar(&initCmd, "init-cmd", "/bin/bash", "entrypoint")
	flag.DurationVar(&dialtimeout, "dialtimeout", 20*time.Second, "dial timeout")

	flag.Var(&flagPassword, "p", "password")
	flag.StringVar(&flagUser, "u", currentUser().Username, "user")
	flag.Parse()
	if version {
		fmt.Printf("sshlib version: %v\n", sshlib.Version)
		os.Exit(0)
	}

	sshlib.Logger = sshlib.NewLogger(&sshlib.LogOptions{
		Name:      "sshlib",
		ShowDebug: verbose,
		ShowErr:   true,
		ShowColor: true,
	})
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func readPass(file string) string {
	b, err := ioutil.ReadFile(file)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func string2color(in string) (r, g, b uint8) {
	md := md5.Sum([]byte(in))
	return md[0], md[1], md[2]
}

func main() {
	manager := sshlib.NewSshManager()
	user, err := user.Lookup(flagUser)
	if err != nil {
		panic(err)
	}
	if sudo {
		manager.SetSudoPassword(readPass(filepath.Join(user.HomeDir, ".secret")))
	}
	manager.User = flagUser
	manager.Password = append(manager.Password, flagPassword...)
	if flagKey == "~/.ssh/id_rsa" {
		manager.Key = filepath.Join(user.HomeDir, ".ssh/id_rsa")
	} else {
		manager.Key = flagKey
	}
	manager.InitCmd = initCmd
	if !verbose {
		manager.Log.SetOutput(ioutil.Discard)
	}

	manager.Prepare()
	manager.ListenningSig()

	skipMap := make(map[string]int)

	lo := log.New(os.Stdout, "", 0)
	go func() {
		d := time.Duration(2 * time.Second)
		t := time.NewTicker(d)
		for {
		HOSTLOOP:
			for _, v := range manager.HostMap {
				t = time.NewTicker(d)
				for {
					select {
					case <-v.Running:
						continue
					case out := <-v.StdOut:
						out = sshlib.CleanResult(out)
						r, g, b := string2color(v.Hostname)
						tag := rgbterm.FgString(fmt.Sprintf("%v:", v.Hostname), r, g, b)
						out = rgbterm.FgString(out, r, g, b)
						if _, ok := skipMap[tag]; !ok {
							skipMap[tag] = skip
						}
						skipMap[tag]--
						if skipMap[tag] < 0 {
							lo.Printf("%v %v\n", tag, out)
						}

					case err := <-v.StdErr:
						err = sshlib.CleanResult(err)
						r, g, b := string2color(v.Hostname)
						tag := rgbterm.FgString(fmt.Sprintf("%v:", v.Hostname), r, g, b)
						err = rgbterm.FgString(err, r, g, b)
						skipMap[tag]--
						if skipMap[tag] < 0 {
							lo.Printf("%v %v\n", tag, err)
						}
						// if output stay in 2s, force run to next
					case <-t.C:
						continue HOSTLOOP
						// if 50ms no result then will escape
					case <-time.After(50 * time.Millisecond):
						continue HOSTLOOP
					}
				}
			}
		}
	}()

	reader := bufio.NewReader(os.Stdin)

	for {
		l, err := reader.ReadString('\n')

		if err != nil {
			if err == io.EOF {
				select {}
			} else {
				Logger.Errorf(err.Error())
				os.Exit(1)
			}
		} else {
			part := strings.Fields(l)
			if len(part) >= 2 && !strings.HasPrefix(part[0], "#") {
				go func(part []string) {
					host := &sshlib.Host{
						Hostname:    part[0],
						ManageIp:    part[1],
						DialTimeout: dialtimeout,
					}
					host = manager.Process(host)

					host.StdIn <- fmt.Sprintf(cmd)
				}(part)
			}
		}
	}
}
