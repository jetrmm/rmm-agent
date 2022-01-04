package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/sarog/rmmagent/agent"
	"github.com/sirupsen/logrus"
)

var (
	version = "1.7.2"
	log     = logrus.New()
	logFile *os.File
)

const AGENT_LOG_FILE = "agent.log"

func main() {
	hostname, _ := os.Hostname()

	// CLI
	ver := flag.Bool("version", false, "Prints agent version and exits")
	mode := flag.String("m", "", "The mode to run: install, update, rpc, agentsvc, runchecks, checkrunner, sysinfo, software, \n\t\tsync, wmi, pk, publicip, getpython, runigrations, taskrunner, cleanup")

	taskPK := flag.Int("p", 0, "Task PK")
	logLevel := flag.String("log", "INFO", "Log level: INFO*, WARN, ERROR, DEBUG")
	logTo := flag.String("logto", "file", "Log destination: file, stdout")

	apiUrl := flag.String("api", "", "API URL")
	clientID := flag.Int("client-id", 0, "Client ID")
	siteID := flag.Int("site-id", 0, "Site ID")
	token := flag.String("auth", "", "Agent's authorization token")

	timeout := flag.Duration("timeout", 1000, "Installer timeout in seconds")
	aDesc := flag.String("desc", hostname, "Agent's description to display on the RMM server")
	aType := flag.String("agent-type", "server", "Agent type: server or workstation")

	power := flag.Bool("power", false, "Disable sleep and hibernate when set to True")
	rdp := flag.Bool("rdp", false, "Enable Remote Desktop Protocol (RDP)")
	ping := flag.Bool("ping", false, "Enable ping and update the Windows Firewall ruleset")
	winDefender := flag.Bool("windef", false, "Add Windows Defender exclusions")
	pythonEnabled := flag.Bool("py-enabled", false, "Enable or disable Python scripts to be executed on this system")
	localMesh := flag.String("local-mesh", "", "Path to the Mesh executable")
	meshDir := flag.String("meshdir", "", "Path to the custom Mesh Central directory") // todo
	noMesh := flag.Bool("nomesh", false, "Do not install the Mesh Agent")              // todo
	cert := flag.String("cert", "", "Path to the Certificate Authority's .pem")

	updateurl := flag.String("updateurl", "", "Source URL to retrieve the update executable")
	inno := flag.String("inno", "", "Inno setup filename")
	updatever := flag.String("updatever", "", "Update version")

	silent := flag.Bool("silent", false, "Do not popup any message boxes during installation")

	flag.Parse()

	if *ver {
		agent.ShowVersionInfo(version)
		return
	}

	if len(os.Args) == 1 {
		agent.ShowStatus(version)
		return
	}

	setupLogging(logLevel, logTo)
	defer logFile.Close()

	a := *agent.New(log, version)

	switch *mode {
	case "rpc":
		a.RunRPCService()
	case "winagentsvc", "agentsvc":
		a.RunAgentService()
	case "runchecks":
		a.RunChecks(true)
	case "checkrunner":
		a.RunChecks(false)
	case "sysinfo":
		a.GetWMI()
	case "software":
		a.SendSoftware()
	case "sync":
		a.Sync()
	case "wmi":
		a.GetWMI()
	case "cleanup":
		a.UninstallCleanup()
	case "publicip":
		fmt.Println(a.PublicIP())
	case "getpython":
		a.GetPython(true)
	case "runmigrations":
		a.RunMigrations()
	case "taskrunner":
		if len(os.Args) < 5 || *taskPK == 0 {
			return
		}
		a.RunTask(*taskPK)
	case "pk":
		fmt.Println(a.AgentPK)
	case "update":
		if *updateurl == "" || *inno == "" || *updatever == "" {
			updateUsage()
			return
		}
		a.AgentUpdate(*updateurl, *inno, *updatever)
	case "install":
		log.SetOutput(os.Stdout)
		if *apiUrl == "" || *clientID == 0 || *siteID == 0 || *token == "" {
			installUsage()
			return
		}
		a.Install(&agent.Installer{
			RMM:           *apiUrl,
			ClientID:      *clientID,
			SiteID:        *siteID,
			Description:   *aDesc,
			AgentType:     *aType,
			Power:         *power,
			RDP:           *rdp,
			Ping:          *ping,
			WinDefender:   *winDefender,
			PythonEnabled: *pythonEnabled,
			Token:         *token,
			LocalMesh:     *localMesh,
			MeshDir:       *meshDir,
			MeshDisabled:  *noMesh,
			Cert:          *cert,
			Timeout:       *timeout,
			Silent:        *silent,
		})
	case "recoversalt":
		a.RecoverSalt()
	case "removesalt":
		a.RemoveSalt()
	default:
		agent.ShowStatus(version)
	}
}

func setupLogging(level, to *string) {
	ll, err := logrus.ParseLevel(*level)
	if err != nil {
		ll = logrus.InfoLevel
	}
	log.SetLevel(ll)

	if *to == "stdout" {
		log.SetOutput(os.Stdout)
	} else {
		switch runtime.GOOS {
		case "windows":
			logFile, _ = os.OpenFile(filepath.Join(os.Getenv("ProgramFiles"), agent.BRANDING_FOLDER, AGENT_LOG_FILE), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)
		case "linux":
			// todo
		}
		log.SetOutput(logFile)
	}
}

func installUsage() {
	switch runtime.GOOS {
	case "windows":
		u := `Usage: %s -m install -api <https://api.example.com> -client-id X -site-id X -auth <TOKEN>`
		fmt.Printf(u, agent.AGENT_FILENAME)
	case "linux":
		// todo
	case "freebsd":
		// todo :)
	}
}

func updateUsage() {
	u := `Usage: %s -m update -updateurl https://example.com/winagent-vX.X.X.exe -inno winagent-vX.X.X.exe -updatever 1.1.1`
	fmt.Printf(u, agent.AGENT_FILENAME)
}
