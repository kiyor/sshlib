package sshlib

import (
	"os"

	"github.com/op/go-logging"
)

type LogOptions struct {
	Name      string
	ShowErr   bool
	ShowDebug bool
	ShowColor bool
}

var (
	Logger *logging.Logger
)

func NewLogger(options *LogOptions) *logging.Logger {
	log := logging.MustGetLogger(options.Name)

	// init default to null
	var out, err *os.File
	if options.ShowErr {
		err = os.Stderr
	}
	if options.ShowDebug {
		out = os.Stdout
	}

	// setup logger
	stdout := logging.NewLogBackend(out, "", 0)
	stderr := logging.NewLogBackend(err, "", 0)

	format := logging.MustStringFormatter(
		"%{time:15:04:05.000} [" + options.Name + "] %{level:.4s} %{id:03x} %{shortfile} %{shortfunc} ▶ \"%{message}\"",
	)
	if options.ShowColor {
		format = logging.MustStringFormatter(
			"%{color}%{time:15:04:05.000} [" + options.Name + "] %{level:.4s} %{id:03x} %{shortfile} %{shortfunc} ▶%{color:reset} \"%{message}\"",
		)
	}

	stdoutFormatter := logging.NewBackendFormatter(stdout, format)
	stderrFormatter := logging.NewBackendFormatter(stderr, format)

	stderrLeveled := logging.AddModuleLevel(stderrFormatter)
	stdoutLeveled := logging.AddModuleLevel(stdoutFormatter)

	stdoutLeveled.SetLevel(logging.DEBUG, "")
	stderrLeveled.SetLevel(logging.ERROR, "")

	logging.SetBackend(stdoutLeveled, stderrLeveled)

	return log
}
