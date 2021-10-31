package sshlib

import (
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"strings"
	"syscall"
	"time"
)

var (
	Manager = NewSshManager()
)

func (manager *SshManager) Prepare() {
	if len(manager.User) == 0 {
		me, err := user.Current()
		if err != nil {
			me, _ = user.LookupId("0")
		}
		manager.User = me.Username
	}

	manager.init()

	manager.Sig = make(chan os.Signal)
	signal.Notify(manager.Sig, syscall.SIGINT, syscall.SIGTERM)

}

func (manager *SshManager) ListenningSig() {
	go func() {
		Logger.Noticef("terminal signal inited")
		select {
		case <-manager.Sig:
			manager.Close()
			os.Exit(0)
		}
	}()
}

func (manager *SshManager) Listenning() {

	manager.Prepare()

	manager.ListenningSig()

	go func() {
		for {
			for _, v := range manager.HostMap {
				select {
				case e := <-v.Err:
					Logger.Errorf("[%s] %v", v.Hostname, e.Error())
				case <-v.Running:
					go func(v *Host) {
						Logger.Noticef("[%s] cmd running detected", v.Hostname)
						v.LastResult = ""
						// do once timeout value bigger
						var run bool
						select {
						case out := <-v.StdOut:
							v.LastResult += fmt.Sprintf("%v\n", out)
							run = true
						case err := <-v.StdErr:
							v.LastResult += fmt.Sprintf("%v\n", err)
							run = true
						case <-time.After(v.FirstCmdTimeout):
							v.LastResult = CleanResult(v.LastResult)
							v.Buckets[len(v.Buckets)-1].Res = v.LastResult
							v.Stopped <- true
							Logger.Noticef("[%s] no more output", v.Hostname)
						}
						if run {
							var b bool
							for {
								select {
								case out := <-v.StdOut:
									v.LastResult += fmt.Sprintf("%v\n", out)
								case err := <-v.StdErr:
									v.LastResult += fmt.Sprintf("%v\n", err)
									// as long as getting something, timeout could be less
								case <-time.After(v.Timeout):
									v.LastResult = CleanResult(v.LastResult)
									v.Buckets[len(v.Buckets)-1].Res = v.LastResult
									v.Stopped <- true
									Logger.Noticef("[%s] no more output", v.Hostname)
									b = true
								}
								if b {
									break
								}
							}
						}
					}(v)
				default:
					continue
				}
			}
		}
	}()
}
func CleanResult(in string) string {
	if len(in) == 0 {
		return in
	}
	p := strings.Split(in, "$")
	if len(p) > 1 && strings.Contains(p[0], "sh-") && len(p[0]) == 6 {
		return strings.Trim(in[8:], "\n")
	}
	return in
}
