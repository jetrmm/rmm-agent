package windows

import (
	"time"

	"github.com/go-resty/resty/v2"

	rmm "github.com/sarog/rmmagent/shared"
)

const API_URL_CHOCO = "/api/v3/choco/"

// InstallChoco Installs the Chocolatey PowerShell script
func (a *windowsAgent) InstallChoco() {

	var result rmm.ChocoInstalled
	result.AgentID = a.AgentID
	result.Installed = false

	rClient := resty.New()
	rClient.SetTimeout(30 * time.Second)

	r, err := rClient.R().Get("https://chocolatey.org/install.ps1")
	if err != nil {
		a.Logger.Debugln(err)
		a.RClient.R().SetBody(result).Post(API_URL_CHOCO)
		return
	}
	if r.IsError() {
		a.RClient.R().SetBody(result).Post(API_URL_CHOCO)
		return
	}

	_, _, exitcode, err := a.RunScript(string(r.Body()), "powershell", []string{}, 900)
	if err != nil {
		a.Logger.Debugln(err)
		a.RClient.R().SetBody(result).Post(API_URL_CHOCO)
		return
	}

	if exitcode != 0 {
		a.RClient.R().SetBody(result).Post(API_URL_CHOCO)
		return
	}

	result.Installed = true
	a.RClient.R().SetBody(result).Post(API_URL_CHOCO)
}

// InstallWithChoco install an application with Chocolatey
func (a *windowsAgent) InstallWithChoco(name string) (string, error) {
	out, err := CMD("choco.exe", []string{"install", name, "--yes", "--force", "--force-dependencies"}, 1200, false)
	if err != nil {
		a.Logger.Errorln(err)
		return err.Error(), err
	}
	if out[1] != "" {
		return out[1], nil
	}
	return out[0], nil
}