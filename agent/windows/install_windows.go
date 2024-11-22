package windows

import (
	"fmt"
	"github.com/jetrmm/go-dpapi"
	"github.com/jetrmm/rmm-agent/agent"
	"github.com/kardianos/service"
	"github.com/sirupsen/logrus"
	windows2 "golang.org/x/sys/windows"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/gonutz/w32/v2"
	nats "github.com/nats-io/nats.go"
	"golang.org/x/sys/windows/registry"
)

type WinRegKeys struct {
	baseUrl  string
	agentId  string
	apiUrl   string
	token    string
	agentPK  string
	pk       int // int(agentPK)
	rootCert string
}

// Install the Agent
func (a *windowsAgent) Install(i *agent.InstallInfo, agentID string) {
	a.checkExistingAndRemove(i.Silent)

	i.Headers = map[string]string{
		"Content-Type":  "application/json",
		"Authorization": fmt.Sprintf("Token %s", i.Token),
	}
	a.AgentID = agentID
	a.Logger.Debugln("Agent ID:", a.AgentID)

	parsedUrl, err := url.Parse(i.ServerURL)
	if err != nil {
		a.installerMsg(err.Error(), "error", i.Silent)
	}

	if parsedUrl.Scheme != "https" && parsedUrl.Scheme != "http" {
		a.installerMsg("Invalid URL: must begin with https or http", "error", i.Silent)
	}

	// This will match either IPv4 or IPv4:port
	var ipPort = regexp.MustCompile(`[0-9]+(?:\.[0-9]+){3}(:[0-9]+)?`)

	// if ipv4:port, strip the port to get ip for NATS
	if ipPort.MatchString(parsedUrl.Host) && strings.Contains(parsedUrl.Host, ":") {
		i.ApiURL = strings.Split(parsedUrl.Host, ":")[0]
	} else if strings.Contains(parsedUrl.Host, ":") {
		i.ApiURL = strings.Split(parsedUrl.Host, ":")[0]
	} else {
		i.ApiURL = parsedUrl.Host
	}

	a.Logger.Debugln("Agent API Endpoint:", i.ApiURL)

	// todo: port 443 and/or 4222
	terr := agent.TestTCP(fmt.Sprintf("%s:%s", i.ApiURL, agent.NATS_DEFAULT_PORT))
	if terr != nil {
		a.installerMsg(fmt.Sprintf("ERROR: Either port %s TCP is not open on your RMM server, or the NATS service is not running.\n\n%s",
			agent.NATS_DEFAULT_PORT, terr.Error()), "error", i.Silent)
	}

	baseURL := parsedUrl.Scheme + "://" + parsedUrl.Host
	a.Logger.Debugln("Base URL:", baseURL)

	iClient := resty.New()
	iClient.SetCloseConnection(true)
	iClient.SetTimeout(15 * time.Second)
	iClient.SetDebug(a.Debug)
	iClient.SetHeaders(i.Headers)
	creds, cerr := iClient.R().Get(fmt.Sprintf("%s/api/v3/installer/", baseURL))
	if cerr != nil {
		a.installerMsg(cerr.Error(), "error", i.Silent)
	}
	if creds.StatusCode() == 401 {
		a.installerMsg("Installer token has expired. Please generate a new one.", "error", i.Silent)
	}

	verPayload := map[string]string{"version": a.Version}

	iVersion, ierr := iClient.R().SetBody(verPayload).Post(fmt.Sprintf("%s/api/v3/installer/", baseURL))
	if ierr != nil {
		a.installerMsg(ierr.Error(), "error", i.Silent)
	}
	if iVersion.StatusCode() != 200 {
		a.installerMsg(iVersion.String(), "error", i.Silent)
	}

	rClient := resty.New()
	rClient.SetCloseConnection(true)
	rClient.SetTimeout(i.Timeout * time.Second)
	rClient.SetDebug(a.Debug)
	rClient.SetHeaders(i.Headers)

	// Set local certificate if applicable
	if len(i.RootCert) > 0 {
		if !agent.FileExists(i.RootCert) {
			a.installerMsg(fmt.Sprintf("%s does not exist", i.RootCert), "error", i.Silent)
		}
		rClient.SetRootCertificate(i.RootCert)
	}

	a.Logger.Infoln("Adding agent to the dashboard")

	type NewAgentResp struct {
		AgentPK int    `json:"pk"`
		Token   string `json:"token"`
	}

	agentPayload := map[string]interface{}{
		"agent_id":    a.AgentID,
		"hostname":    a.GetHostname(),
		"client":      i.ClientID,
		"site":        i.SiteID,
		"description": i.Description,
		// -sg: "monitoring_type": i.AgentType,
	}

	r, err := rClient.R().SetBody(agentPayload).SetResult(&NewAgentResp{}).Post(fmt.Sprintf("%s/api/v3/newagent/", baseURL))
	if err != nil {
		a.installerMsg(err.Error(), "error", i.Silent)
	}
	if r.StatusCode() != 200 {
		a.installerMsg(r.String(), "error", i.Silent)
	}

	agentPK := r.Result().(*NewAgentResp).AgentPK
	authToken := r.Result().(*NewAgentResp).Token

	// a.Logger.Debugln("Agent Token:", authToken)
	a.Logger.Debugln("Agent PK:", agentPK)

	createRegKeys(baseURL, a.AgentID, i.ApiURL, authToken, strconv.Itoa(agentPK), i.RootCert)

	// Refresh our agent with new values
	// was: a = a.New(a.Logger, a.Version, true)
	a = NewAgent(a.Logger, a.Version, true)

	// Set new headers. No longer knox auth; use agent auth
	rClient.SetHeaders(a.Headers)

	// Send WMI system information
	a.Logger.Debugln("Getting system information via WMI")
	a.SysInfo()

	// Check in once via NATS
	opts := a.SetupNatsOptions()
	server := fmt.Sprintf("tls://%s:%d", a.ApiURL, a.ApiPort)

	nc, err := nats.Connect(server, opts...)
	if err != nil {
		a.Logger.Errorln(err)
	} else {
		startup := []string{CHECKIN_MODE_HELLO, CHECKIN_MODE_OSINFO, CHECKIN_MODE_WINSERVICES, CHECKIN_MODE_DISKS, CHECKIN_MODE_PUBLICIP, CHECKIN_MODE_SOFTWARE, CHECKIN_MODE_LOGGEDONUSER}
		for _, mode := range startup {
			a.CheckIn(nc, mode)
			time.Sleep(200 * time.Millisecond)
		}
		nc.Close()
	}

	a.Logger.Debugln("Creating temporary directory")
	a.CreateAgentTempDir()

	a.Logger.Infoln("Installing service...")
	serr := a.InstallService()
	if serr != nil {
		return
	}

	a.installerMsg("Installation was successful!\nPlease allow a few minutes for the agent to show up in the RMM server", "info", i.Silent)
}

// InstallService todo: Installs the agent service
func (a *windowsAgent) InstallService() error {
	s, _ := service.New(a, a.GetServiceConfig())
	err := s.Install()
	if err != nil {
		return err
	}

	return nil
}

// todo: add to Agent interface
func (a *windowsAgent) checkExistingAndRemove(silent bool) {
	hasReg := false
	_, err := registry.OpenKey(registry.LOCAL_MACHINE, REG_RMM_PATH, registry.ALL_ACCESS)
	if err == nil {
		hasReg = true
	}
	if hasReg {
		jetUninst := filepath.Join(a.GetWorkingDir(), a.GetUninstallExe())
		jetUninstArgs := []string{jetUninst, "/VERYSILENT", "/SUPPRESSMSGBOXES", "/FORCECLOSEAPPLICATIONS"}

		window := w32.GetForegroundWindow()
		if !silent && window != 0 {
			var handle w32.HWND
			msg := "Existing installation found\nClick OK to remove, then re-run the installer.\nClick Cancel to abort."
			action := w32.MessageBox(handle, msg, agent.AGENT_NAME_LONG, w32.MB_OKCANCEL|w32.MB_ICONWARNING)
			if action == w32.IDOK {
				a.AgentUninstall()
			}
		} else {
			fmt.Println("Existing installation found and must be removed before attempting to reinstall.")
			fmt.Println("Run the following command to uninstall, and then re-run this installer.")
			fmt.Printf(`"%s" %s %s %s`, jetUninstArgs[0], jetUninstArgs[1], jetUninstArgs[2], jetUninstArgs[3])
		}
		os.Exit(0)
	}
}

func createRegKeys(baseUrl, agentId, apiUrl, token, agentPK, rootCert string) {
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, REG_RMM_PATH, registry.ALL_ACCESS)
	if err != nil {
		log.Fatalln("Error creating registry key:", err)
	}
	defer key.Close()

	err = key.SetStringValue(REG_RMM_BASEURL, baseUrl)
	if err != nil {
		log.Fatalln("Error creating BaseURL registry key:", err)
	}

	err = key.SetStringValue(REG_RMM_AGENTID, agentId)
	if err != nil {
		log.Fatalln("Error creating AgentID registry key:", err)
	}

	err = key.SetStringValue(REG_RMM_APIURL, apiUrl)
	if err != nil {
		log.Fatalln("Error creating ApiURL registry key:", err)
	}

	token, err = dpapi.EncryptMachineLocal(token)
	if err != nil {
		log.Fatalln("Unable to encrypt Token:", err)
	}

	err = key.SetStringValue(REG_RMM_TOKEN, token)
	if err != nil {
		log.Fatalln("Error creating Token registry key:", err)
	}

	err = key.SetStringValue(REG_RMM_AGENTPK, agentPK)
	if err != nil {
		log.Fatalln("Error creating AgentPK registry key:", err)
	}

	if len(rootCert) > 0 {
		err = key.SetStringValue(REG_RMM_CERT, rootCert)
		if err != nil {
			log.Fatalln("Error creating RootCert registry key:", err)
		}
	}
}

func getRegKeys(logger *logrus.Logger) (*WinRegKeys, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, REG_RMM_PATH, registry.READ)
	if err != nil {
		return nil, err
	}

	baseUrl, _, err := key.GetStringValue(REG_RMM_BASEURL)
	if err != nil {
		logger.Fatalln("Unable to get BaseURL:", err)
	}

	agentId, _, err := key.GetStringValue(REG_RMM_AGENTID)
	if err != nil {
		logger.Fatalln("Unable to get AgentID:", err)
	}

	apiUrl, _, err := key.GetStringValue(REG_RMM_APIURL)
	if err != nil {
		logger.Fatalln("Unable to get ApiURL:", err)
	}

	token, _, err := key.GetStringValue(REG_RMM_TOKEN)
	if err != nil {
		logger.Fatalln("Unable to get Token:", err)
	}

	token, err = dpapi.Decrypt(token)
	if err != nil {
		logger.Fatalln("Unable to decrypt Token:", err)
	}

	agentPK, _, err := key.GetStringValue(REG_RMM_AGENTPK)
	if err != nil {
		logger.Fatalln("Unable to get AgentPK:", err)
	}

	pk, _ := strconv.Atoi(agentPK)

	rootCert, _, _ := key.GetStringValue(REG_RMM_CERT)

	return &WinRegKeys{
		baseUrl:  baseUrl,
		agentId:  agentId,
		apiUrl:   apiUrl,
		token:    token,
		agentPK:  agentPK,
		pk:       pk,
		rootCert: rootCert,
	}, nil
}

func (a *windowsAgent) installerMsg(msg, alert string, silent bool) {
	window := w32.GetForegroundWindow()
	if !silent && window != 0 {
		var (
			handle w32.HWND
			flags  uint
		)

		switch alert {
		case "info":
			flags = w32.MB_OK | w32.MB_ICONINFORMATION
		case "error":
			flags = w32.MB_OK | w32.MB_ICONERROR
		default:
			flags = w32.MB_OK | w32.MB_ICONINFORMATION
		}

		w32.MessageBox(handle, msg, agent.AGENT_NAME_LONG, flags)
	} else {
		fmt.Println(msg)
	}

	if alert == "error" {
		a.Logger.Fatalln(msg)
	}
}

func (a *windowsAgent) UninstallCleanup() {
	err := registry.DeleteKey(registry.LOCAL_MACHINE, REG_RMM_PATH)
	if err != nil {
		return
	}
	a.CleanupAgentUpdates()
	CleanupSchedTasks()
}

func (a *windowsAgent) AgentUpdate(url, inno, version string) {
	time.Sleep(time.Duration(randRange(1, 15)) * time.Second)

	a.CleanupAgentUpdates()

	updater := filepath.Join(a.GetWorkingDir(), inno)
	a.Logger.Infof("Agent updating from %s to %s", a.Version, version)
	a.Logger.Infoln("Downloading agent update from", url)

	rClient := resty.New()
	rClient.SetCloseConnection(true)
	rClient.SetTimeout(15 * time.Minute)
	rClient.SetDebug(a.Debug)
	r, err := rClient.R().SetOutput(updater).Get(url)
	if err != nil {
		a.Logger.Errorln(err)
		runExe("net", []string{"start", SERVICE_NAME_AGENT}, 10, false)
		return
	}
	if r.IsError() {
		a.Logger.Errorln("Download failed with status code", r.StatusCode())
		runExe("net", []string{"start", SERVICE_NAME_AGENT}, 10, false)
		return
	}

	dir, err := os.MkdirTemp("", INNO_SETUP_DIR)
	if err != nil {
		a.Logger.Errorln("AgentUpdate unable to create temporary directory:", err)
		runExe("net", []string{"start", SERVICE_NAME_AGENT}, 10, false)
		return
	}

	innoLogFile := filepath.Join(dir, INNO_SETUP_LOGFILE)

	args := []string{"/C", updater, "/VERYSILENT", fmt.Sprintf("/LOG=%s", innoLogFile)}
	cmd := exec.Command("cmd.exe", args...)
	cmd.SysProcAttr = &windows2.SysProcAttr{
		CreationFlags: windows2.DETACHED_PROCESS | windows2.CREATE_NEW_PROCESS_GROUP,
	}
	cmd.Start()
	time.Sleep(1 * time.Second)
}

func (a *windowsAgent) GetUninstallExe() string {
	cderr := os.Chdir(a.GetWorkingDir())
	if cderr == nil {
		files, err := filepath.Glob("unins*.exe")
		if err == nil {
			for _, f := range files {
				if strings.Contains(f, "001") {
					return f
				}
			}
		}
	}
	return "unins000.exe"
}

func (a *windowsAgent) AgentUninstall() {
	agentUninst := filepath.Join(a.GetWorkingDir(), a.GetUninstallExe())
	args := []string{"/C", agentUninst, "/VERYSILENT", "/SUPPRESSMSGBOXES", "/FORCECLOSEAPPLICATIONS"}
	cmd := exec.Command("cmd.exe", args...)
	cmd.SysProcAttr = &windows2.SysProcAttr{
		CreationFlags: windows2.DETACHED_PROCESS | windows2.CREATE_NEW_PROCESS_GROUP,
	}
	cmd.Start()
}

func (a *windowsAgent) CleanupAgentUpdates() {
	cderr := os.Chdir(a.GetWorkingDir())
	if cderr != nil {
		a.Logger.Errorln(cderr)
		return
	}

	files, err := filepath.Glob("winagent-v*.exe")
	if err == nil {
		for _, f := range files {
			os.Remove(f)
		}
	}

	cderr = os.Chdir(os.Getenv("TMP"))
	if cderr != nil {
		a.Logger.Errorln(cderr)
		return
	}
	folders, err := filepath.Glob(RMM_SEARCH_PREFIX)
	if err == nil {
		for _, f := range folders {
			os.RemoveAll(f)
		}
	}
}
