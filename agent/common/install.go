package common

import "time"

type InstallInfo struct {
	Headers     map[string]string
	ServerURL   string // dupe?
	ApiURL      string // NATS URL
	ClientID    int
	SiteID      int
	Description string
	// AgentType   string // Workstation, Server
	Token    string // dupe?
	RootCert string
	Timeout  time.Duration
	Silent   bool
}