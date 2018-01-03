Windows-Audit
---------
Scripts for auditing Windows Server 2003+ servers.

These scripts will gather a vast array of information about one or many targeted Windows servers and serialise the information to disk. The scripts will then compile the data into an Excel spreadsheet for review using a _filter_ to report on only the desired data. More information on Filters can be found in the dedicated readme file located at `.\Filters\Filters.md`.

The serialised data for servers will remain cached until another gathering operation is run, at which point the data will be refreshed. This allows you to run a single gathering, and reparse the same data into a variety of different views.

Prerequisites
---------
##### Calling Client
PowerShell v3 is the minimum client requirement. For machines which do not have WinRM installed/enabled, you can use PSExec which you can download [here](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec).

##### Target Server
Connections over WinRM will require the [Windows Management Framework](https://support.microsoft.com/en-gb/help/968929/windows-management-framework-windows-powershell-2-0--winrm-2-0--and-bi) v2 as a minimum with TCP port `5985` allowed from the calling client. Alternatively if using PSExec you can view a list of requirements [here](https://forum.sysinternals.com/psexec-could-not-start_topic3698_post11962.html#11962). Powershell v2 and above have been verified, v1 has not been tested.

Usage
---------
There are a variety of sub scripts and modules however for simplicity the execution has been consolodated into a single script; `Invoke-WindowsAudit.ps1`.

##### Mandatory Parameters

 - `InputFile` - The path to a text file which contains the computer list you wish to audit, one per line. An example of this file can be found here `.\Examples\Computer-List-Example.txt`. Mutually exclusive with the `Computers` parameter.

 - `Computers` - String array of computers to audit. Mutually exclusive with the `InputFile` parameter.

 - `PSCredential` - PSCredential that will be used to connect to the target machines. More information on how to use PSCredentials can be found [here](https://blogs.msdn.microsoft.com/koteshb/2010/02/12/powershell-how-to-create-a-pscredential-object/).

##### Optional Parameters

 - `Compile` - This switch when present tells the script to do a compilation of the just-gathered data to an Excel spreadsheet. If this is supplied; the `Filter` parameter _must also_ be supplied.

 - `CompileOnly` - This switch when present tells the script to do a compilation of the cached data to an Excel spreadsheet. If this is supplied; the `Filter` parameter _must also_ be supplied.

 - `Filter` - The name of the filter you wish to apply to the dataset. Must exist in the `.\Filters` directory with a `.ps1` file extension. An example filter has been supplied with this solution with the name of `Example`.

##### Examples

This example will invoke an audit data gathering on the computers specified in the `ExampleComputerList.txt` file using the `$MyPSCredential` credential, and will then compile the data into an Excel spreadsheet using the `Example` filter.
```PowerShell
.\Invoke-WindowsAudit.ps1 `
    -InputFile ".\ExampleComputerList.txt" `
    -PSCredential $MyPSCredential `
    -Compile `
    -Filter "Example";
```

<br />

This example will invoke an audit data gathering on the computers specified in the Computers parameter. Because the `Compile` switch has not been specified, no further processing will take place after the data has been gathered.
```PowerShell
.\Invoke-WindowsAudit.ps1 -Computers "dev-test-01","dev-test-02";
```

<br />

This example will invoke a compilation against existing cached data using the `Example` filter.
```PowerShell
.\Invoke-WindowsAudit.ps1 -CompileOnly -Filter "Example";
```

Output Example
---------
See the `Output-Example.xlsx` file in the `Examples` folder.

Future Development
---------
 - Further expand upon Apache/Tomcat sections
 - Write a proper PS type adapter for the WebAdministration module types and use this to expand on IIS properties
 - Drill down into _all_ roles and features and gather status/configuration
 - Test for PowerShell v1 compatibility
 - Write bottom-line script to execute locally (for airgapped machines), output CLI XML file for manual move and compilation