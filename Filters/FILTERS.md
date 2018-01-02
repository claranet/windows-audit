Filters
---------

Filters are a way of taking the original gathered data and presenting different elements in different ways. The example filters provided will output the below table of data, splitting out each section into an individual Excel worksheet (or SQL table for the SQL version).

The filter needs to be defined as a single `PSCustomObject` with named key value pairs indicating the name (key) of the section you wish to create, along with the actual content (value) of that section. If the value object is enumerable, you can use the subexpression `$( $subexpression )` syntax to enumerate the property into a pipeline and capture (or filter) the named values you wish to obtain from the object. You can see an example of this in action in the `Example-SQL.ps1` and `Example-Excel.ps1` filters.

The `$HostInformation` parameter that gets passede into the filter can be accessed using dot notation to obtain the properties you seek. For a full property map please see the [properties map](#full-property-map) below.

Example Filter
---------
##### System Information (key:value)
	- HostName
	- Domain Name
	- IPv4 Address
	- OS
	- Uptime
	- Region/Locale
	- Timezone
	- System Type
	- Make
	- Model
	- Service Tag
	- BIOS Info
	- Asset Tag
	- PowerShell Version
	- .NET Version
	- CPU
	- Total Physical Memory
	- Available Physical Memory
	- Virtual Memory Max Size
	- Virtual Memory Available
	- Virtual Memory InUse
	- Is Virtual Machine
	
##### Network Interfaces (table)
	- HostName
	- Description
	- Adapter Index
	- IPv4 Address
	- IPv6 Address
	- Domain Name
	- Subnet Mask
	- Gateway
	- DNS Servers
	
##### Firewall Rules (table)
	- HostName
	- Name
	- Description
	- Local Ports
	- Remote Ports
	- Local Addresses
	- Remote Addresses
	- Direction
	
##### TLS Certificates (table)
	- HostName
	- Friendly Name
	- Expires
	- Thumbprint
	- Has Private Key
	- Issuer
	
##### Storage Disks (table)
	- HostName
	- Disk Type
	- Interface Type
	- Media Type
	- Size
	
##### Storage Volumes (table)
	- HostName
	- Caption
	- Mount Point
	- Type
	- Filesystem
	- Boot Volume
	- System Volume
	- Indexing Enabled
	- Page file present
	- Compressed
	- Free Space
	- Used Space
	- Total Size
	
##### Shared Folders and Drives (table)
	- HostName
	- Shared Folder Path
	- Shared Folder Name
	- Shared Folder Description
	- Shared Folder Permissions
	- Mounted Drive Path
	- Mounted Drive Letter
	
##### Applications (table)
	- HostName
	- Display Name
	- Display Version
	- Publisher
	- Install Date
	- Help Link
	
##### Windows Features (table)
	- HostName
	- Display Name
	- Name
	- Feature Type
	- Path
	- Subfeatures
	
##### Scheduled Tasks (table)
	- HostName
	- Name
	- Enabled
	- Actions
	- Last Run Time
	- Last Result

##### USB Devices (table)
	- HostName
	- Name
	- Caption
	- Description
	- Manufacturer
	- Service
	- Status

##### Serial Devices (table)
	- HostName
	- Caption
	- Name
	- PNP Device ID
	- Status

##### IIS Information (table)
	- HostName
	- Site Name
	- Bindings
	- Physical Path
	- Folder Dependencies (Experimental)
	- SQL Dependencies (Experimental)
	- Web Dependencies (Experimental)

##### Database Information (table)
	- HostName
	- Instance Name
	- Connection Identifier
	- SQL Version
	- Is Accessible
	- DB Name
	- DB Owner
	- DB Created Date
	- DB Compatibility Level
	- DB ID
	- DB Size
	- DB Status
	- DB Updateability
	- DB User Access
	- DB Recovery Mode
	- DB Version
	- DB Collation
	- DB Sort Order
	- DB Auto Create Statistics
	- DB Auto Update Statistics

##### Windows Updates (table)
	- HostName
	- Description
	- Service Pack In Effect
	- Fix Comments
	- Installed On
	- Caption
	- Name
	- Hotfix ID
	- Status
	- Install Date
	- Install By

##### Network Topology (table)
	- HostName
	- Protocol
	- Local Address
	- Local Port
	- Remote Address
	- Remote Port
	- State
	- Process ID
	- Process Name
	- Process Description
	- Process Product
	- Process File Version
	- Process Exe Path
	- Process Company

Full property map
---------
Some Notes:

* The `Win32_USBControllerDevice` class is enumerated by the `[Wmi]$_.Dependent` property in order to obtain the connected devices. If you are chaining multiple USB hub type devices your output may not be captured. In this circumstance you can modify line `#13` in the `Win32_USBControllerDevice.ps1` file to further enumerate this.

* The `Win32_Share` class also has an additional `$_.SharePermissions` property added, which you can use to view the share permissions.

* The `Win32_PNPEntity` class can be filtered using the `ClassGUID` of `{4d36e978-e325-11ce-bfc1-08002be10318}` to obtain Serial devices only.

* _All_ of the property groups (including WMI) contain a `MachineIdentifier` property, this can be used to correlate rows from different tables/worksheets to the same machine. Should you be using SQL to compile the results, _be sure to include this in your filter for more efficient joins._

#### WMI Classes
Click on the WMI class name for a full list of properties from the MSDN.

| WMI Class  | HostInformation Property  |
|---|---|
| [Win32_OperatingSystem](https://msdn.microsoft.com/en-us/library/aa394239(v=vs.85).aspx) | `$_.Win32_OperatingSystem` |
| [Win32_ComputerSystem](https://msdn.microsoft.com/en-us/library/aa394102(v=vs.85).aspx) | `$_.Win32_ComputerSystem` |
| [Win32_BIOS](https://msdn.microsoft.com/en-us/library/aa394077(v=vs.85).aspx) | `$_.Win32_BIOS` |
| [Win32_Processor](https://msdn.microsoft.com/en-us/library/aa394373(v=vs.85).aspx) | `$_.Win32_Processor` |
| [Win32_PhysicalMemory](https://msdn.microsoft.com/en-us/library/aa394347(v=vs.85).aspx) | `$_.Win32_PhysicalMemory` |
| [Win32_DiskDrive](https://msdn.microsoft.com/en-us/library/aa394132(v=vs.85).aspx) | `$_.Win32_DiskDrive` |
| [Win32_LogicalDisk](https://msdn.microsoft.com/en-us/library/aa394173(v=vs.85).aspx) | `$_.Win32_LogicalDisk` |
| [Win32_Volume](https://msdn.microsoft.com/en-us/library/aa394515(v=vs.85).aspx) | `$_.Win32_Volume` |
| [Win32_Share](https://msdn.microsoft.com/en-us/library/aa394435(v=vs.85).aspx) | `$_.Win32_Share` |
| [Win32_MappedLogicalDisk](https://msdn.microsoft.com/en-us/library/aa394194(v=vs.85).aspx) | `$_.Win32_MappedLogicalDisk` |
| [Win32_NetworkAdapterConfiguration](https://msdn.microsoft.com/en-us/library/aa394217(v=vs.85).aspx) | `$_.Win32_NetworkAdapterConfiguration` |
| [Win32_USBControllerDevice](https://msdn.microsoft.com/en-us/library/aa394505(v=vs.85).aspx) | `$_.Win32_USBControllerDevice` |
| [Win32_PNPEntity](https://msdn.microsoft.com/en-us/library/aa394353%28v=vs.85%29.aspx) | `$_.Win32_PNPEntity` |
| [Win32_Printer](https://msdn.microsoft.com/en-us/library/aa394363(v=vs.85).aspx) | `$_.Win32_Printer` |
| [Win32_Service](https://msdn.microsoft.com/en-us/library/aa394418(v=vs.85).aspx) | `$_.Win32_Service` |

#### Other Available Properties

| Property Description  | HostInformation Property  | Contains |
|---|---|---|
| Applications | `$_.Applications` | DisplayName<br/> DisplayVersion<br/> InstallLocation<br/> Publisher<br/> HelpLink |
| IIS Sites | `$_.IISSites` | IISVersion<br/> Type<br/> Name<br/> ID<br/> State<br/> PhysicalPath<br/> Bindings<br/> ApplicationPoolName<br/> ApplicationPoolState<br/> ApplicationPoolIdentityType<br/> ApplicationPoolUser<br/> ApplicationPoolManagedPipelineMode<br/> ApplicationPoolManagedRuntimeVersion<br/> ApplicationPoolStartMode<br/> ApplicationPoolAutoStart |
| IIS Configuration | `$_.IISSitesConfiguration` | IISVersion<br/> Name<br/> ID<br/> SitePath<br/> ConfigurationFileName<br/> ConfigurationFilePath<br/> ConfigurationFileContent |
| SQL Server Instances | `$_.SQLServerInstances` | InstanceName<br/> InstanceVersion<br/> ConnectionIdentifier<br/> Accessible |
| SQL Server Database | `$_.SQLServerDatabases` | InstanceName<br/> ConnectionIdentifier<br/> Name<br/> Size<br/> Owner<br/> DBID<br/> CreatedDate<br/> Status<br/> CompatibilityLevel |
| Firewall Configuration | `$_.FirewallConfiguration` | ProfileName<br/> FileName<br/> UnicastResponseToMulticast<br/> RemoteManagement<br/> LogAllowedConnections<br/> LogDroppedConnections<br/> State<br/> Firewall<br/> InboundUserNotification<br/> MaxFileSize |
| Firewall Rules | `$_.FirewallRules` | Name<br/> Enabled<br/> Direction<br/> Profiles<br/> Grouping<br/> LocalAddresses<br/> RemoteAddresses<br/> Protocol<br/> LocalPorts<br/> RemotePorts<br/> EdgeTraversal |
| Network Connections (Netstat) | `$_.NetworkConnections` | Protocol<br/> LocalAddress<br/> LocalPort<br/> RemoteAddress<br/> RemotePort<br/> State<br/> ProcessID<br/> ProcessName<br/> ProcessDescription<br/> ProcessProduct<br/> ProcessFileVersion<br/> ProcessExePath<br/> ProcessCompany |
| Roles & Features | `$_.RolesAndFeatures` | MachineVersion<br/> DisplayName<br/> Name<br/> FeatureType<br/> Path<br/> Subfeatures<br/> Installed |
| Scheduled Tasks | `$_.ScheduledTasks` | Name<br/> Enabled<br/> NextRunTime<br/> Status<br/> LogonMode<br/> LastRunTime<br/> LastResult<br/> Author<br/> TaskToRun<br/> StartIn<br/> Comment<br/> IdleTime<br/> PowerManagement<br/> RunAsUser<br/> DeleteIfNotRescheduled<br/> StopIfOverrun<br/> ScheduleType<br/> StartTime<br/> StartDate<br/> EndDate<br/> Days<br/> Months<br/> RepeatEvery<br/> RepeatUntil<br/> RepeatUntilDuration<br/> RepeatStopIfStillRunning |
| System Properties | `$_.SystemProperties` | PowerShellVersion<br/> DotNetVersion<br/> Location |
| Time Configuration | `$_.Time` | AnnounceFlags<br/> EventLogs<br/> FrequencyCorrectRate<br/> HoldPeriod<br/> LargePhaseOffset<br/> LocalClockDispersion<br/> MaxAllowedPhaseOffset<br/> MaxNegPhaseCorrection<br/> MaxPollInterval<br/> PaxPosPhaseCorrection<br/> MinPollInterval<br/> PhaseCorrectRate<br/> PollAdjustFactor<br/> Server<br/> SpikeWatchPeriod<br/> TimeJumpAuditOffset<br/> Type<br/> UpdateInterval |
| TLS Certificates | `$_.TLSCertificates` | EnhancedKeyUsageList<br/> DnsNameList<br/> SendAsTrustedIssuer<br/> EnrollmentPolicyEndPoint<br/> EnrollmenterverEndPoint<br/> PolicyId<br/> Archived<br/> Extension<br/> FriendlyName<br/> IssuerName<br/> NotAfter<br/> NotBefore<br/> HasPrivateKey<br/> PublicKey<br/> SerialNumber<br/> SubjectName<br/> SignatureAlgorithm<br/> Thumbprint<br/> Version<br/> Handle<br/> Issuer<br/> Subject | 
| Windows Updates | `$_.WindowsUpdates` | Caption<br/> CSName<br/> Description<br/> FixComments<br/> HotFixID<br/> InstallDate<br/> InstalledBy<br/> InstalledOn<br/> Name<br/> ServicePackInEffect<br/> Status |