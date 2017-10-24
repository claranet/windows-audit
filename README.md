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

 - `Compile` - This switch when present tells the script to do a compilation of the data to an Excel spreadsheet. If this is supplied; the -Filter parameter _must also_ be supplied

 - `Filter` - The name of the filter you wish to apply to the dataset. Must exist in the .\Filters directory with a .ps1 file extension.

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
_wip_

Output format
---------
_wip_

Data gathering map
---------
_wip_

Specification
---------
**[Claranet Internal Only](https://docs.google.com/spreadsheets/d/1rXc9RkPcsKet6uE8ZYqiOJ1GEwWHeesa0cMfADgdObY/)**