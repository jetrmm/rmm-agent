package darwin

import (
	"github.com/jetrmm/rmm-agent/agent"
)

func init() {
	agent.Register(darwinAgent{})
}

type darwinAgent struct {
	agent.Agent
}
