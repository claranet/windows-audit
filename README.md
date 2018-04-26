Windows-Audit
---------
Scripts for auditing Windows Server 2003+ servers.

These scripts will gather a vast array of information about one or many targeted Windows servers and serialise the information to disk. You can then compile the data into an Excel spreadsheet or SQL database for review using a _filter_ to report on only the desired data. More information on Filters can be found in the dedicated readme file located at `.\Filters\Filters.md`. The process is multithreaded so many jobs can run in parallel.

The serialised data for servers will remain cached until another gathering operation is run, at which point the data will be refreshed. This allows you to run a single gathering, and reparse the same data into a variety of different views.

Prerequisites
---------
##### Calling Client
Connections over WinRM will require the [Windows Management Framework](https://www.microsoft.com/en-us/download/details.aspx?id=50395) v5 as a minimum and a Windows credential that is valid on the target machine. Excel compilation does _not_ require Excel but you will require [dfinke's ImportExcel module](https://github.com/dfinke/ImportExcel). For SQL compilation any version of Microsoft SQL Server above 2005 will be required, as well as the [SQL Server PowerShell module](https://docs.microsoft.com/en-us/sql/ssms/download-sql-server-ps-module).  

##### Target Server
Connections over WinRM will require the [Windows Management Framework](https://support.microsoft.com/en-gb/help/968929/windows-management-framework-windows-powershell-2-0--winrm-2-0--and-bi) v2 as a minimum with TCP port `5985` allowed from the calling client. Powershell v2 and above has been verified, v1 has not been tested (but _may_ work).

Usage
---------
##### Node Hints File
Before you begin your audit you must create a _Node Hints_ file, an example of this file can be found in the Examples directory. You can use NetBIOS and DNS names, as well as IP addresses and CIDR blocks to express the list of machines for your audit.

Each line must begin with an include `>` or exclude `<` operator followed immediately by the NetBIOS|DNS|IP|CIDR, this allows you the flexibility of defining a range using a CIDR block yet exclude specific IP addresses (or even other CIDR blocks) from that range easily. Any other line that does not start with one of these operators will be ignored as a comment.

CIDR blocks will be expanded and added to the list of nodes to scan, in exactly the same way as if you had put in a line for each IP in the range. This may take some time depending on the complexity of the ranges you have specified, however there is a progress bar to tell you what's happening every step of the way.

The final stage of discovering nodes from the hints file is to apply the exclusions, this ensures that all CIDR blocks are fully expanded before deciding which nodes should/shouldn't be included.

##### Scripts
There are a variety of sub scripts and modules however for simplicity the execution has been consolodated into two top level scripts; `Get-AuditData.ps1` and `Compile-AuditData.ps1` (run in that order to gather => compile).

##### Get-AuditData Parameters
| Parameter | Purpose | Type | Default/Mandatory |
|---|---|---|---|
| `PSCredential` | Credential used to authenticate when gathering data | PSCredential | Mandatory |
| `NodeHintsFile` | File path to the [Node Hints file](#node-hints-file) | String | Mandatory |
| `ThreadCount` | Number of threads to use for the probe/audit process | Int | `64` |

##### Get-AuditData Example
This example will invoke an audit data gathering on the nodes specified in the Node Hints file using the $MyPSCredential credential, and a custom thread count of 128. You will need to experiment with the `ThreadCount` parameter and find the sweet spot for the machine you're running the audit from.

```PowerShell
.\Get-AuditData.ps1 -PSCredential $MyPSCredential -NodeHintsFile ".\nodehints.txt" -ThreadCount 128;
```

<br />

##### Compile-AuditData Parameters
| Parameter | Purpose | Type | Default/Mandatory |
|---|---|---|---|
| `CompilationType` | Which medium to compile the data to | String [SQL,Excel] | Mandatory |
| `Filter` | Name of the [Filter](/Filters/Filters.md) to use when compiling | String | Mandatory |
| `SQLServerName` | The `server\instance` name of the SQL server for compilation | String | Mandatory if `CompilationType` is SQL |
| `SQLDatabaseName` | The name of the SQL database name for compilation | String | Mandatory if `CompilationType` is SQL |

##### Get-AuditData Examples
This example will compile the data you have previously gathered using the `Example` filter, outputting the data to Excel.

```PowerShell
.\Compile-AuditData.ps1 -CompilationType "Excel" -Filter "Example";
```

This example will compile the data you have previously gathered using the `Example` filter, outputting the data to the `AuditData` database on the server `SQL01`.

```PowerShell
.\Compile-AuditData.ps1 -CompilationType "SQL" -Filter "Example" -SQLServerName "SQL01" -SQLServerDatabase "AuditData";
```

Excel Output Example
---------
See the `Filtered-Audit-Data-Example.xlsx` file in the `Examples` folder.
