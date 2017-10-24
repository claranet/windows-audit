Windows-Audit
---------
Scripts for auditing Windows Server 2003+ servers.

These scripts will gather a vast array of information about one or many targeted Windows servers and serialise the information to disk. The scripts will then compile the data into an Excel spreadsheet for review using a _filter_ to report on only the desired data.

The serialised data for servers will remain cached until another gathering operation is run, at which point the data will be refreshed. This allows you to run a single gathering, and reparse the same data into a variety of different views.

Prerequisites
---------
##### Calling Client
Connections over WinRM will require the [Windows Management Framework](https://support.microsoft.com/en-gb/help/968929/windows-management-framework-windows-powershell-2-0--winrm-2-0--and-bi) v2 as a minimum and a Windows credential that is valid on the target machine. For machines which have not got WinRM installed, you can use [PSExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) instead.

##### Target Server
Connections over WinRM will require the [Windows Management Framework](https://support.microsoft.com/en-gb/help/968929/windows-management-framework-windows-powershell-2-0--winrm-2-0--and-bi) v2 as a minimum with TCP port `5985` allowed from the calling client. Alternatively if using PSExec TCP port `445` needs to be opened. Powershell v2 and above has been verified, v1 has not been tested.

Usage
---------
There are a variety of sub scripts and modules however for simplicity the execution has been consolodated into a single script; `Invoke-WindowsAudit.ps1`.

##### Mandatory Parameters

 - `InputFile` - The path to a Pipe Separated Values file which will be parsed for target information on what instances to harvest audit data from. The per-line format should be `(hostname|ip):(port)|(protocol)`. An example of this file can be found in `.\Input\ExampleComputerList.psv`.

**or**

 - `Computers` - String array of computers to run this script on. If the computer value is a `host:port` or `ip:port` combination the specified port will be used for WinRM (only).

##### Optional Parameters

 - `Protocol` - The protocol to use for the target computers specified in the `$Computers` parameter. Valid options are `WinRM`|`PSExec` defaulting to `WinRM` if not specified.

 - `PSCredential` - PSCredential that will be used for WinRM communications. Must be valid on the machines you're trying to connect to, defaults to the current user identity.

 - `SerialisationDepth` - Override value for the serialisation depth to use when this script is using the `System.Management.Automation.PSSerializer` class. Defaults to `5` and range is limited to `2..8`; as anything less than `2` is useless, anything greater than `8` will generate a _very_ large (multi-gb) file and probably crash the targeted machine. Tweak this value only if the data you want is nested so low in the dataset it's not being enumerated in the output.

 - `Compile` - This switch when present tells the script to do a compilation of the data to an Excel spreadsheet. If this is supplied; the `Filter` parameter _must also_ be supplied

 - `Filter` - The name of the filter you wish to apply to the dataset. Must exist in the `.\Filters` directory with a `.ps1` file extension. An example filter has been supplied with this solution with the name of `Example`.

##### Examples

This example will invoke an audit data gathering on the computers specified in the `MyComputerList.psv` file using the `$MyPSCredential` credential for machines targeted with WinRM, and will then compile the data into an Excel spreadsheet using the `Example` filter.
```PowerShell
    .\Invoke-WindowsAudit.ps1 `
            -InputFile ".\Input\MyComputerList.psv" `
            -PSCredential $MyPSCredential `
            -Compile `
            -Filter "Example";
```

<br />

This example will invoke an audit data gathering on the computers specified in the Computers parameter using the PSExec protocol. Because the `Compile` switch has not been specified, no further processing will take place after the data has been gathered.
```PowerShell
.\Invoke-WindowsAudit.ps1 `
        -Computers "dev-test-01","dev-test-02" `
        -Protocol PSExec;
```

Filters
---------
Filters are a way of taking the original gathered data and presenting different elements in different ways. The example filter provided will output the below table of data, splitting out each section into an individual Excel worksheet.

The filter needs to be defined as a single `PSCustomObject` with named key value pairs indicating the name (key) of the section you wish to create, along with the actual content (value) of that section. If the value object is enumerable, you can use the subexpression `$( $subexpression )` syntax to enumerate the property into a pipeline and capture (or filter) the named values you wish to obtain from the object. You can see an example of this in action in the `.\Filters\Example.ps1` file.

The `$HostInformation` parameter that gets passede into the filter can be accessed using dot notation to obtain the properties you seek. For a full property map please see the [properties map]() below.

##### System Information (key:value)
	- HostName
	- Domain Name
	- IPv4 Address
	- OS
	- Uptime
	- Region/Locale
	- Timezone
	- System Type
	- Location
	- WSUS Server
	- PowerShell Version
	- .NET Version
	- CPU
	- CPU Use % (Total)
	- Total Physical Memory
	- Available Physical Memory
	- Virtual Memory Max Size
	- Virtual Memory Available
	- Virtual Memory InUse
	
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
	- Mounted Drive Path
	- Mounted Drive Letter
	
##### Applications (table)
	- HostName
	- Display Name
	- Display Version
	- Publisher
	- Install Date
	- Install Type
	
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

Full property map
---------
The script that gets executed on the named target will gather the following information:

#### WMI Classes
Click on the WMI class name for a full list of methods and properties from the MSDN.

| WMI Class  | HostInformation Property  |
|---|---|
| [Win32_OperatingSystem](https://msdn.microsoft.com/en-us/library/aa394239(v=vs.85).aspx) | `$_.OS` |
| [Win32_ComputerSystem](https://msdn.microsoft.com/en-us/library/aa394102(v=vs.85).aspx) | `$_.SystemInfo.SystemInfo` |
| [Win32_Processor](https://msdn.microsoft.com/en-us/library/aa394373(v=vs.85).aspx) | `$_.Compute` |
| [Win32_PhysicalMemory](https://msdn.microsoft.com/en-us/library/aa394347(v=vs.85).aspx) | `$_.Memory.PhysicalMemory` |
| [Win32_DiskDrive](https://msdn.microsoft.com/en-us/library/aa394132(v=vs.85).aspx) | `$_.Storage.PhysicalDisks` |
| [Win32_LogicalDisk](https://msdn.microsoft.com/en-us/library/aa394173(v=vs.85).aspx) | `$_.Storage.LogicalDisks` |
| [Win32_Volume](https://msdn.microsoft.com/en-us/library/aa394515(v=vs.85).aspx) | `$_.Storage.Volumes` |
| [Win32_Share](https://msdn.microsoft.com/en-us/library/aa394435(v=vs.85).aspx) | `$_.Storage.SharedFolders` |
| [Win32_MappedLogicalDisk](https://msdn.microsoft.com/en-us/library/aa394194(v=vs.85).aspx) | `$_.Storage.MountedDrives` |
| [Win32_NetworkAdapterConfiguration](https://msdn.microsoft.com/en-us/library/aa394217(v=vs.85).aspx) | `$_.Networking.AdapterInformation` |
| [Win32_USBControllerDevice](https://msdn.microsoft.com/en-us/library/aa394505(v=vs.85).aspx) | `$_.Peripherals.USBDevices` |
| [Win32_SerialPort](https://msdn.microsoft.com/en-us/library/aa394413(v=vs.85).aspx) | `$_.Peripherals.SerialDevices` |
| [Win32_Printer](https://msdn.microsoft.com/en-us/library/aa394363(v=vs.85).aspx) | `$_.Peripherals.Printers` |
| [Win32_Service](https://msdn.microsoft.com/en-us/library/aa394418(v=vs.85).aspx) | `$_.WindowsServices` |

_(Note: the `Win32_USBControllerDevice` class is enumerated by the `[Wmi]$_.Dependent` property in order to obtain the connected devices. If you are using certain types of USB hub to chain multiple devices your output may not be captured. In this circumstance you can modify line `#286` in the `.\_Lib\Audit-Scriptblock.ps1` file to further enumerate this.)_

#### Other Available Properties

| Property Description  | HostInformation Property  | Contains |
|---|---|---|
| Hostname | `$_.SystemInfo.HostName` | String |
| Is Virtual Machine | `$_.SystemInfo.IsVirtualMachine` | String |
| Machine Type | `$_.SystemInfo.MachineType` | String |
| Location | `$_.SystemInfo.Location` | String |
| CPU % Total Use | `$_.SystemInfo.CPUPercentInUse` | String |
| Total Physical Memory | `$_.Memory.WindowsMemory.TotalPhysicalMemory` | String |
| Available Physical Memory | `$_.Memory.WindowsMemory.AvailablePhysicalMemory` | String |
| Virtual Memory Max Size | `$_.Memory.WindowsMemory.VirtualMemoryMaxSize` | String |
| Virtual Memory Available | `$_.Memory.WindowsMemory.VirtualMemoryAvailable` | String |
| Virtual Memory In Use | `$_.Memory.WindowsMemory.VirtualMemoryInUse` | String |
| NTP Configuration | `$_.Networking.NTPConfiguration` | Output from `w32tm /query /configuration` |
| Firewall Zone | `$_.Networking.FirewallZone` | String |
| Firewall Rules | `$_.Networking.FirewallRules` | Name<br/> Description<br/> ApplicationName<br/> serviceName<br/> Protocol<br/> LocalPorts<br/> RemotePorts<br/> LocalAddresses<br/> RemoteAddresses<br/> IcmpTypesAndCodes<br/> Direction<br/> Interfaces<br/> InterfaceTypes<br/> Enabled<br/> Grouping<br/> Profiles<br/> EdgeTraversal<br/> Action<br/> EdgeTraversalOptions<br/> LocalAppPackageId<br/> LocalUserOwner<br/> LocalUserAuthorizedList<br/> RemoteUserAuthorizedList<br/> RemoteMachineAuthorizedList<br/> SecureFlags |
| Installed Apps (x32) | `$_.Applications.x32` | DisplayName<br /> DisplayVersion<br /> Publisher<br /> InstallDate |
| Installed Apps (x64) | `$_.Applications.x64` | DisplayName<br /> DisplayVersion<br /> Publisher<br /> InstallDate |
| Windows Roles & Features | `$_.RolesAndFeatures` | Name<br /> Installed<br /> FeatureType<br /> Path<br /> Depth<br /> DependsOn<br /> Parent<br /> SubFeatures<br /> SystemService<br /> Notification<br /> BestPracticesModelId<br /> AdditionalInfo<br /> |
| IIS WebSites | `$_.IISConfiguration.WebSites` | ID<br /> Name<br /> Bindings<br /> PhysicalPath<br /> State<br /> |
| IIS App Pools | `$_.IISConfiguration.ApplicationPools` | Name<br /> AutoStart<br /> Applications<br /> StartMode<br /> State<br /> ManagedRuntimeVersion<br /> ManagedPipelineMode<br /> |
| IIS Web Bindings | `$_.IISConfiguration.WebBindings` | BindingInformation<br /> Protocol</br> |
| IIS Virtual Dirs | `$_.IISConfiguration.VirtualDirectories` | PhysicalPath<br /> Name<br /> Path<br /> |
| IIS Config Files | `$_.IISConfiguration.ConfigurationFiles` | XML Content of associated *.config files |
| TLS Certificates | `$_.TLSCertificates` | PSPath<br /> PSParentPath<br /> PSChildName<br /> PSDrive<br /> PSProvider<br /> PSIsContainer<br /> Archived<br /> Extensions<br /> FriendlyName<br /> IssuerName<br /> NotAfter<br /> NotBefore<br /> HasPrivateKey<br /> PrivateKey<br /> PublicKey<br /> RawData<br /> SerialNumber<br /> SubjectName<br /> SignatureAlgorithm<br /> Thumbprint<br /> Version<br /> Handle<br /> Issuer<br /> Subject<br /> |
| Windows Updates History | `$_.WindowsUpdates.UpdateHistory` | Title<br /> Description<br /> Date<br /> Operation<br /> |
| WSUS Server | `$_.WindowsUpdates.WSUSServer` | String |
| PowerShell Version | `$_.Management.PowerShellVersion` | String |
| .NET Version | `$_.Management.DotNetVersion` | String |
| WinRM Enabled | `$_.Management.WinRMEnabled` | String |
| Scheduled Tasks | $_.ScheduledTasks | NextRunTime<br /> State<br /> Actions<br /> Path<br /> Name<br /> LastRunTime<br /> MissedRuns<br /> LastResult<br /> Enabled<br /> |
| DC Info | `$_.ActiveDirectoryDomainController.DomainController` | ComputerObjectDN<br /> DefaultPartition<br /> Domain<br /> Enabled<br /> Forest<br /> HostName<br /> InvocationId<br /> IPv4Address<br /> IPv6Address<br /> IsGlobalCatalog<br /> IsReadOnly<br /> LdapPort<br /> Name<br /> NTDSSettingsObjectDN<br /> OperatingSystem<br /> OperatingSystemHotfix<br /> OperatingSystemServicePack<br /> OperatingSystemVersion<br /> OperationMasterRoles<br /> Partitions<br /> ServerObjectDN<br /> ServerObjectGuid<br /> Site<br /> SslPort<br /> PropertyNames<br /> PropertyCount<br /> |
| Domain Info | `$_.ActiveDirectoryDomainController.Domain` | AllowedDNSSuffixes<br /> ChildDomains<br /> ComputersContainer<br /> DeletedObjectsContainer<br /> DistinguishedName<br /> DNSRoot<br /> DomainControllersContainer<br /> DomainMode<br /> DomainSID<br /> ForeignSecurityPrincipalsContainer<br /> Forest<br /> InfrastructureMaster<br /> LastLogonReplicationInterval<br /> LinkedGroupPolicyObjects<br /> LostAndFoundContainer<br /> ManagedBy<br /> Name<br /> NetBIOSName<br /> ObjectClass<br /> ObjectGUID<br /> ParentDomain<br /> PDCEmulator<br /> QuotasContainer<br /> ReadOnlyReplicaDirectoryServers<br /> ReplicaDirectoryServers<br /> RIDMaster<br /> SubordinateReferences<br /> SystemsContainer<br /> UsersContainer<br /> PropertyNames<br /> PropertyCount<br /> |
| Forest Info | `$_.ActiveDirectoryDomainController.Forest` | ApplicationPartitions<br /> CrossForestReferences<br /> DomainNamingMaster<br /> Domains<br /> ForestMode<br /> GlobalCatalogs<br /> Name<br /> PartitionsContainer<br /> RootDomain<br /> SchemaMaster<br /> Sites<br /> SPNSuffixes<br /> UPNSuffixes<br /> PropertyNames<br /> PropertyCount<br /> |
| Directory Service Specific Entries |  `$_.ActiveDirectoryDomainController.DSE` | configurationNamingContext<br /> currentTime<br /> defaultNamingContext<br /> dnsHostName<br /> domainControllerFunctionality<br /> domainFunctionality<br /> dsServiceName<br /> forestFunctionality<br /> highestCommittedUSN<br /> isGlobalCatalogReady<br /> isSynchronized<br /> ldapServiceName<br /> namingContexts<br /> rootDomainNamingContext<br /> schemaNamingContext<br /> serverName<br /> subschemaSubentry<br /> supportedCapabilities<br /> supportedControl<br /> supportedLDAPPolicies<br /> supportedLDAPVersion<br /> supportedSASLMechanisms<br /> Synchronized<br /> GlobalCatalogReady<br /> PropertyNames<br /> PropertyCount<br /> |
| DC Diag |  `$_.ActiveDirectoryDomainController.DCDiag` | Output from `dcdiag` |
| SQL Database List | `$_.SQLServer.DatabaseList` | String[] of database names |
| SQL Database Information | `$_.SQLServer.DatabaseInformation` | Output from `SP_HELPDB` for all databases |
| Apache Virtual Hosts | `$_.ApacheVirtualHosts` | String[] of Virtual Hosts |
| Tomcat Applications | `$_.TomcatApplications` | String[] of applications |

Output Example
---------
**[Claranet Internal Only](https://docs.google.com/spreadsheets/d/1rXc9RkPcsKet6uE8ZYqiOJ1GEwWHeesa0cMfADgdObY/)**

Future Development
---------
 - Coalesce SQL server properties into a single table with `Instances > Databases > SP_HELPDB` structure
 - Further expand upon Apache/Tomcat sections
 - Write a proper PS type adapter for the WebAdministration module types and use this to expand on IIS properties
 - Drill down into _all_ roles and features and gather status/configuration
 - Test for PowerShell v1 compatibility
 - Write bottom-line script to execute locally (for airgapped machines), output CLI XML file for manual move and compilation