package linux

import (
	"github.com/jetrmm/rmm-agent/agent"
)

func init() {
	agent.Register(linuxAgent{})
}

type linuxAgent struct {
	agent.Agent
}
