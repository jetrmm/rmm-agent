package shared

import "time"

type WinUpdateResult struct {
	AgentID string       `json:"agent_id"`
	Updates []WUAPackage `json:"wua_updates"`
}

type WUAPackage struct {
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Categories     []string `json:"categories"`
	CategoryIDs    []string `json:"category_ids"`
	KBArticleIDs   []string `json:"kb_article_ids"`
	MoreInfoURLs   []string `json:"more_info_urls"`
	SupportURL     string   `json:"support_url"`
	UpdateID       string   `json:"guid"`
	RevisionNumber int32    `json:"revision_number"`
	Severity       string   `json:"severity"`
	Installed      bool     `json:"installed"`
	Downloaded     bool     `json:"downloaded"`
}

type WinUpdateInstallResult struct {
	AgentID  string `json:"agent_id"`
	UpdateID string `json:"guid"`
	Success  bool   `json:"success"`
}

type SupersededUpdate struct {
	AgentID  string `json:"agent_id"`
	UpdateID string `json:"guid"`
}

type PkgMgrInstalled struct {
	AgentID        string `json:"agent_id"`
	Installed      bool   `json:"installed"`
	PackageManager string `json:"package_manager"`
}

// WindowsService holds Windows service info
type WindowsService struct {
	Name             string `json:"name"`
	Status           string `json:"status"`
	DisplayName      string `json:"display_name"`
	BinPath          string `json:"binpath"`
	Description      string `json:"description"`
	Username         string `json:"username"`
	PID              uint32 `json:"pid"`
	StartType        string `json:"start_type"`
	DelayedAutoStart bool   `json:"autodelay"`
}

// Deprecated
type CheckInWinServices struct {
	AgentHeader
	Services []WindowsService `json:"services"`
}

type EventLogMsg struct {
	Source    string `json:"source"`
	EventType string `json:"eventType"`
	EventID   uint32 `json:"eventID"`
	Message   string `json:"message"`
	Time      string `json:"time"`
	// Deprecated
	UID int `json:"uid"` // for vue
}

type Win32_ComputerSystemProduct struct {
	Caption           string
	Description       string
	IdentifyingNumber string
	Name              string
	SKUNumber         string
	Vendor            string
	Version           string
	UUID              string
}

type Win32_ComputerSystemEX struct {
	AdminPasswordStatus       uint16
	AutomaticManagedPagefile  bool
	AutomaticResetBootOption  bool
	AutomaticResetCapability  bool
	BootOptionOnLimit         uint16
	BootOptionOnWatchDog      uint16
	BootROMSupported          bool
	BootupState               string
	Caption                   string
	ChassisBootupState        uint16
	ChassisSKUNumber          string //
	CreationClassName         string
	CurrentTimeZone           int16
	DaylightInEffect          bool
	Description               string
	DNSHostName               string
	Domain                    string
	DomainRole                uint16
	EnableDaylightSavingsTime bool
	FrontPanelResetStatus     uint16
	HypervisorPresent         bool //
	InfraredSupported         bool
	InstallDate               time.Time
	KeyboardPasswordStatus    uint16
	Manufacturer              string
	Model                     string
	Name                      string
	NameFormat                string
	NetworkServerModeEnabled  bool
	NumberOfLogicalProcessors uint32
	NumberOfProcessors        uint32
	OEMStringArray            []string
	PartOfDomain              bool
	PauseAfterReset           int64
	PCSystemType              uint16
	PCSystemTypeEx            uint16 //
	PowerManagementSupported  bool
	PowerOnPasswordStatus     uint16
	PowerState                uint16
	PowerSupplyState          uint16
	PrimaryOwnerContact       string
	PrimaryOwnerName          string
	ResetCapability           uint16
	ResetCount                int16
	ResetLimit                int16
	Roles                     []string
	Status                    string
	SupportContactDescription []string
	SystemFamily              string //
	SystemSKUNumber           string //
	SystemType                string
	ThermalState              uint16
	TotalPhysicalMemory       uint64
	UserName                  string
	WakeUpType                uint16
	Workgroup                 string
}

type Win32_ComputerSystem struct {
	AdminPasswordStatus       uint16
	AutomaticManagedPagefile  bool
	AutomaticResetBootOption  bool
	AutomaticResetCapability  bool
	BootOptionOnLimit         uint16
	BootOptionOnWatchDog      uint16
	BootROMSupported          bool
	BootupState               string
	Caption                   string
	ChassisBootupState        uint16
	CreationClassName         string
	CurrentTimeZone           int16
	DaylightInEffect          bool
	Description               string
	DNSHostName               string
	Domain                    string
	DomainRole                uint16
	EnableDaylightSavingsTime bool
	FrontPanelResetStatus     uint16
	InfraredSupported         bool
	InstallDate               time.Time
	KeyboardPasswordStatus    uint16
	Manufacturer              string
	Model                     string
	Name                      string
	NameFormat                string
	NetworkServerModeEnabled  bool
	NumberOfLogicalProcessors uint32
	NumberOfProcessors        uint32
	OEMStringArray            []string
	PartOfDomain              bool
	PauseAfterReset           int64
	PCSystemType              uint16
	PowerManagementSupported  bool
	PowerOnPasswordStatus     uint16
	PowerState                uint16
	PowerSupplyState          uint16
	PrimaryOwnerContact       string
	PrimaryOwnerName          string
	ResetCapability           uint16
	ResetCount                int16
	ResetLimit                int16
	Roles                     []string
	Status                    string
	SupportContactDescription []string
	SystemType                string
	ThermalState              uint16
	TotalPhysicalMemory       uint64
	UserName                  string
	WakeUpType                uint16
	Workgroup                 string
}

type Win32_NetworkAdapterConfiguration struct {
	Caption                      string
	Description                  string
	SettingID                    string
	ArpAlwaysSourceRoute         bool
	ArpUseEtherSNAP              bool
	DatabasePath                 string
	DeadGWDetectEnabled          bool
	DefaultIPGateway             []string
	DefaultTOS                   uint8
	DefaultTTL                   uint8
	DHCPEnabled                  bool
	DHCPLeaseExpires             time.Time
	DHCPLeaseObtained            time.Time
	DHCPServer                   string
	DNSDomain                    string
	DNSDomainSuffixSearchOrder   []string
	DNSEnabledForWINSResolution  bool
	DNSHostName                  string
	DNSServerSearchOrder         []string
	DomainDNSRegistrationEnabled bool
	ForwardBufferMemory          uint32
	FullDNSRegistrationEnabled   bool
	IGMPLevel                    uint8
	Index                        uint32
	InterfaceIndex               uint32
	IPAddress                    []string
	IPConnectionMetric           uint32
	IPEnabled                    bool
	IPFilterSecurityEnabled      bool
	IPSecPermitIPProtocols       []string
	IPSecPermitTCPPorts          []string
	IPSecPermitUDPPorts          []string
	IPSubnet                     []string
	IPUseZeroBroadcast           bool
	KeepAliveInterval            uint32
	KeepAliveTime                uint32
	MACAddress                   string
	MTU                          uint32
	NumForwardPackets            uint32
	PMTUBHDetectEnabled          bool
	PMTUDiscoveryEnabled         bool
	ServiceName                  string
	TcpipNetbiosOptions          uint32
	TcpMaxConnectRetransmissions uint32
	TcpMaxDataRetransmissions    uint32
	TcpNumConnections            uint32
	TcpUseRFC1122UrgentPointer   bool
	TcpWindowSize                uint16
	WINSEnableLMHostsLookup      bool
	WINSHostLookupFile           string
	WINSPrimaryServer            string
	WINSScopeID                  string
	WINSSecondaryServer          string
}

type Win32_PhysicalMemoryEX struct {
	Attributes           uint32 //
	BankLabel            string
	Capacity             uint64
	Caption              string
	ConfiguredClockSpeed uint32 //
	ConfiguredVoltage    uint32 //
	CreationClassName    string
	DataWidth            uint16
	Description          string
	DeviceLocator        string
	FormFactor           uint16
	HotSwappable         bool
	InstallDate          time.Time
	InterleaveDataDepth  uint16
	InterleavePosition   uint32
	Manufacturer         string
	MaxVoltage           uint32 //
	MemoryType           uint16
	MinVoltage           uint32 //
	Model                string
	Name                 string
	OtherIdentifyingInfo string
	PartNumber           string
	PositionInRow        uint32
	PoweredOn            bool
	Removable            bool
	Replaceable          bool
	SerialNumber         string
	SKU                  string
	SMBIOSMemoryType     uint32 //
	Speed                uint32
	Status               string
	Tag                  string
	TotalWidth           uint16
	TypeDetail           uint16
	Version              string
}

type Win32_PhysicalMemory struct {
	BankLabel            string
	Capacity             uint64
	Caption              string
	CreationClassName    string
	DataWidth            uint16
	Description          string
	DeviceLocator        string
	FormFactor           uint16
	HotSwappable         bool
	InstallDate          time.Time
	InterleaveDataDepth  uint16
	InterleavePosition   uint32
	Manufacturer         string
	MemoryType           uint16
	Model                string
	Name                 string
	OtherIdentifyingInfo string
	PartNumber           string
	PositionInRow        uint32
	PoweredOn            bool
	Removable            bool
	Replaceable          bool
	SerialNumber         string
	SKU                  string
	Speed                uint32
	Status               string
	Tag                  string
	TotalWidth           uint16
	TypeDetail           uint16
	Version              string
}

type Win32_OperatingSystem struct {
	BootDevice                 string
	BuildNumber                string
	BuildType                  string
	Caption                    string
	CodeSet                    string
	CountryCode                string
	CreationClassName          string
	CSCreationClassName        string
	CSDVersion                 string
	CSName                     string
	CurrentTimeZone            int16
	Debug                      bool
	Description                string
	Distributed                bool
	EncryptionLevel            uint32
	ForegroundApplicationBoost uint8
	FreePhysicalMemory         uint64
	FreeSpaceInPagingFiles     uint64
	FreeVirtualMemory          uint64
	InstallDate                time.Time
	LastBootUpTime             time.Time
	LocalDateTime              time.Time
	Locale                     string
	Manufacturer               string
	MaxNumberOfProcesses       uint32
	MaxProcessMemorySize       uint64
	MUILanguages               []string
	Name                       string
	NumberOfLicensedUsers      uint32
	NumberOfProcesses          uint32
	NumberOfUsers              uint32
	OperatingSystemSKU         uint32
	Organization               string
	OSArchitecture             string
	OSLanguage                 uint32
	OSProductSuite             uint32
	OSType                     uint16
	OtherTypeDescription       string
	PAEEnabled                 bool
	PlusProductID              string
	PlusVersionNumber          string
	Primary                    bool
	ProductType                uint32
	RegisteredUser             string
	SerialNumber               string
	ServicePackMajorVersion    uint16
	ServicePackMinorVersion    uint16
	SizeStoredInPagingFiles    uint64
	Status                     string
	SuiteMask                  uint32
	SystemDevice               string
	SystemDirectory            string
	SystemDrive                string
	TotalSwapSpaceSize         uint64
	TotalVirtualMemorySize     uint64
	TotalVisibleMemorySize     uint64
	Version                    string
	WindowsDirectory           string
}

type Win32_BaseBoard struct {
	Caption                 string
	ConfigOptions           []string
	CreationClassName       string
	Depth                   float32
	Description             string
	Height                  float32
	HostingBoard            bool
	HotSwappable            bool
	InstallDate             time.Time
	Manufacturer            string
	Model                   string
	Name                    string
	OtherIdentifyingInfo    string
	PartNumber              string
	PoweredOn               bool
	Product                 string
	Removable               bool
	Replaceable             bool
	RequirementsDescription string
	RequiresDaughterBoard   bool
	SerialNumber            string
	SKU                     string
	SlotLayout              string
	SpecialRequirements     bool
	Status                  string
	Tag                     string
	Version                 string
	Weight                  int32
	Width                   int32
}

type Win32_BIOSEX struct {
	BIOSVersion                    []string
	BuildNumber                    string
	Caption                        string
	CodeSet                        string
	CurrentLanguage                string
	Description                    string
	EmbeddedControllerMajorVersion uint8 //
	EmbeddedControllerMinorVersion uint8 //
	IdentificationCode             string
	InstallableLanguages           uint16
	InstallDate                    time.Time
	LanguageEdition                string
	ListOfLanguages                []string
	Manufacturer                   string
	Name                           string
	OtherTargetOS                  string
	PrimaryBIOS                    bool
	ReleaseDate                    time.Time
	SerialNumber                   string
	SMBIOSBIOSVersion              string
	SMBIOSMajorVersion             uint16
	SMBIOSMinorVersion             uint16
	SMBIOSPresent                  bool
	SoftwareElementID              string
	SoftwareElementState           uint16
	Status                         string
	SystemBiosMajorVersion         uint8 //
	SystemBiosMinorVersion         uint8 //
	TargetOperatingSystem          uint16
	Version                        string
}

type Win32_BIOS struct {
	BIOSVersion           []string
	BuildNumber           string
	Caption               string
	CodeSet               string
	CurrentLanguage       string
	Description           string
	IdentificationCode    string
	InstallableLanguages  uint16
	InstallDate           time.Time
	LanguageEdition       string
	ListOfLanguages       []string
	Manufacturer          string
	Name                  string
	OtherTargetOS         string
	PrimaryBIOS           bool
	ReleaseDate           time.Time
	SerialNumber          string
	SMBIOSBIOSVersion     string
	SMBIOSMajorVersion    uint16
	SMBIOSMinorVersion    uint16
	SMBIOSPresent         bool
	SoftwareElementID     string
	SoftwareElementState  uint16
	Status                string
	TargetOperatingSystem uint16
	Version               string
}

type Win32_DiskDrive struct {
	Availability             uint16
	BytesPerSector           uint32
	CapabilityDescriptions   []string
	Caption                  string
	CompressionMethod        string
	ConfigManagerErrorCode   uint32
	ConfigManagerUserConfig  bool
	CreationClassName        string
	DefaultBlockSize         uint64
	Description              string
	DeviceID                 string
	ErrorCleared             bool
	ErrorDescription         string
	ErrorMethodology         string
	FirmwareRevision         string
	Index                    uint32
	InstallDate              time.Time
	InterfaceType            string
	LastErrorCode            uint32
	Manufacturer             string
	MaxBlockSize             uint64
	MaxMediaSize             uint64
	MediaLoaded              bool
	MediaType                string
	MinBlockSize             uint64
	Model                    string
	Name                     string
	NeedsCleaning            bool
	NumberOfMediaSupported   uint32
	Partitions               uint32
	PNPDeviceID              string
	PowerManagementSupported bool
	SCSIBus                  uint32
	SCSILogicalUnit          uint16
	SCSIPort                 uint16
	SCSITargetId             uint16
	SectorsPerTrack          uint32
	SerialNumber             string
	Signature                uint32
	Size                     uint64
	Status                   string
	StatusInfo               uint16
	SystemCreationClassName  string
	SystemName               string
	TotalCylinders           uint64
	TotalHeads               uint32
	TotalSectors             uint64
	TotalTracks              uint64
	TracksPerCylinder        uint32
}

type Win32_NetworkAdapter struct {
	AdapterType              string
	AdapterTypeID            uint16
	AutoSense                bool
	Availability             uint16
	Caption                  string
	ConfigManagerErrorCode   uint32
	ConfigManagerUserConfig  bool
	CreationClassName        string
	Description              string
	DeviceID                 string
	ErrorCleared             bool
	ErrorDescription         string
	GUID                     string
	Index                    uint32
	InstallDate              time.Time
	InterfaceIndex           uint32
	LastErrorCode            uint32
	MACAddress               string
	Manufacturer             string
	MaxNumberControlled      uint32
	MaxSpeed                 uint64
	Name                     string
	NetConnectionID          string
	NetConnectionStatus      uint16
	NetEnabled               bool
	NetworkAddresses         []string
	PermanentAddress         string
	PhysicalAdapter          bool
	PNPDeviceID              string
	PowerManagementSupported bool
	ProductName              string
	ServiceName              string
	Speed                    uint64
	Status                   string
	StatusInfo               uint16
	SystemCreationClassName  string
	SystemName               string
	TimeOfLastReset          time.Time
}

type Win32_DesktopMonitor struct {
	Availability             uint16
	Bandwidth                uint32
	Caption                  string
	ConfigManagerErrorCode   uint32
	ConfigManagerUserConfig  bool
	CreationClassName        string
	Description              string
	DeviceID                 string
	DisplayType              uint16
	ErrorCleared             bool
	ErrorDescription         string
	InstallDate              time.Time
	IsLocked                 bool
	LastErrorCode            uint32
	MonitorManufacturer      string
	MonitorType              string
	Name                     string
	PixelsPerXLogicalInch    uint32
	PixelsPerYLogicalInch    uint32
	PNPDeviceID              string
	PowerManagementSupported bool
	ScreenHeight             uint32
	ScreenWidth              uint32
	Status                   string
	StatusInfo               uint16
	SystemCreationClassName  string
	SystemName               string
}

type Win32_ProcessorEX struct {
	AddressWidth                            uint16
	Architecture                            uint16
	AssetTag                                string //
	Availability                            uint16
	Caption                                 string
	Characteristics                         uint32 //
	ConfigManagerErrorCode                  uint32
	ConfigManagerUserConfig                 bool
	CpuStatus                               uint16
	CreationClassName                       string
	CurrentClockSpeed                       uint32
	CurrentVoltage                          uint16
	DataWidth                               uint16
	Description                             string
	DeviceID                                string
	ErrorCleared                            bool
	ErrorDescription                        string
	ExtClock                                uint32
	Family                                  uint16
	InstallDate                             time.Time
	L2CacheSize                             uint32
	L2CacheSpeed                            uint32
	L3CacheSize                             uint32
	L3CacheSpeed                            uint32
	LastErrorCode                           uint32
	Level                                   uint16
	LoadPercentage                          uint16
	Manufacturer                            string
	MaxClockSpeed                           uint32
	Name                                    string
	NumberOfCores                           uint32
	NumberOfEnabledCore                     uint32 //
	NumberOfLogicalProcessors               uint32
	OtherFamilyDescription                  string
	PartNumber                              string //
	PNPDeviceID                             string
	PowerManagementSupported                bool
	ProcessorId                             string
	ProcessorType                           uint16
	Revision                                uint16
	Role                                    string
	SecondLevelAddressTranslationExtensions bool   //
	SerialNumber                            string //
	SocketDesignation                       string
	Status                                  string
	StatusInfo                              uint16
	Stepping                                string
	SystemCreationClassName                 string
	SystemName                              string
	ThreadCount                             uint32 //
	UniqueId                                string
	UpgradeMethod                           uint16
	Version                                 string
	VirtualizationFirmwareEnabled           bool //
	VMMonitorModeExtensions                 bool //
	VoltageCaps                             uint32
}

type Win32_Processor struct {
	AddressWidth              uint16
	Architecture              uint16
	Availability              uint16
	Caption                   string
	ConfigManagerErrorCode    uint32
	ConfigManagerUserConfig   bool
	CpuStatus                 uint16
	CreationClassName         string
	CurrentClockSpeed         uint32
	CurrentVoltage            uint16
	DataWidth                 uint16
	Description               string
	DeviceID                  string
	ErrorCleared              bool
	ErrorDescription          string
	ExtClock                  uint32
	Family                    uint16
	InstallDate               time.Time
	L2CacheSize               uint32
	L2CacheSpeed              uint32
	L3CacheSize               uint32
	L3CacheSpeed              uint32
	LastErrorCode             uint32
	Level                     uint16
	LoadPercentage            uint16
	Manufacturer              string
	MaxClockSpeed             uint32
	Name                      string
	NumberOfCores             uint32
	NumberOfLogicalProcessors uint32
	OtherFamilyDescription    string
	PNPDeviceID               string
	PowerManagementSupported  bool
	ProcessorId               string
	ProcessorType             uint16
	Revision                  uint16
	Role                      string
	SocketDesignation         string
	Status                    string
	StatusInfo                uint16
	Stepping                  string
	SystemCreationClassName   string
	SystemName                string
	UniqueId                  string
	UpgradeMethod             uint16
	Version                   string
	VoltageCaps               uint32
}

type Win32_USBController struct {
	Availability             uint16
	Caption                  string
	ConfigManagerErrorCode   uint32
	ConfigManagerUserConfig  bool
	CreationClassName        string
	Description              string
	DeviceID                 string
	ErrorCleared             bool
	ErrorDescription         string
	InstallDate              time.Time
	LastErrorCode            uint32
	Manufacturer             string
	MaxNumberControlled      uint32
	Name                     string
	PNPDeviceID              string
	PowerManagementSupported bool
	ProtocolSupported        uint16
	Status                   string
	StatusInfo               uint16
	SystemCreationClassName  string
	SystemName               string
	TimeOfLastReset          time.Time
}

type Win32_VideoController struct {
	AcceleratorCapabilities   []string
	AdapterCompatibility      string
	AdapterDACType            string
	AdapterRAM                uint32
	Availability              uint16
	CapabilityDescriptions    []string
	Caption                   string
	CurrentRefreshRate        uint32
	CurrentVerticalResolution uint32
	Description               string
	DeviceID                  string
	DriverDate                time.Time
	DriverVersion             string
	InstallDate               time.Time
	InstalledDisplayDrivers   string
	MaxMemorySupported        uint32
	MaxRefreshRate            uint32
	MinRefreshRate            uint32
	Name                      string
	Status                    string
	SystemCreationClassName   string
	SystemName                string
	TimeOfLastReset           time.Time
	VideoModeDescription      string
	VideoProcessor            string
}
