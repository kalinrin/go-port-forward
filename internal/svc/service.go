// Package svc wraps kardianos/service for cross-platform service management.
package svc

import (
	"os"

	"go-port-forward/internal/logger"

	"github.com/kardianos/service"
)

// Config is the system service configuration.
type Config struct {
	Name        string
	DisplayName string
	Description string
}

// Runner is the callback that starts and stops the application logic.
type Runner interface {
	Start() error
	Stop() error
}

type program struct {
	runner Runner
}

func (p *program) Start(s service.Service) error {
	go func() {
		if err := p.runner.Start(); err != nil {
			logger.S.Errorw("service start failed, exiting", "err", err)
			logger.Sync()
			// Exit non-zero so the service manager (systemd/launchd/SCM)
			// records a failed start instead of reporting the service as
			// running. Partially started subsystems are released by the
			// process exit itself.
			os.Exit(1)
		}
	}()
	return nil
}

func (p *program) Stop(s service.Service) error {
	return p.runner.Stop()
}

// Install installs the binary as a system service.
func Install(cfg Config) error {
	svc, err := build(cfg, nil)
	if err != nil {
		return err
	}
	return svc.Install()
}

// Uninstall removes the system service registration.
func Uninstall(cfg Config) error {
	svc, err := build(cfg, nil)
	if err != nil {
		return err
	}
	return svc.Uninstall()
}

// Run registers runner and hands control to the service manager.
// On interactive terminals this just calls runner.Start() directly.
func Run(cfg Config, runner Runner) error {
	svc, err := build(cfg, runner)
	if err != nil {
		return err
	}
	return svc.Run()
}

func build(cfg Config, runner Runner) (service.Service, error) {
	p := &program{runner: runner}
	sc := &service.Config{
		Name:        cfg.Name,
		DisplayName: cfg.DisplayName,
		Description: cfg.Description,
	}
	return service.New(p, sc)
}
