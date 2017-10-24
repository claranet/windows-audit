#requires -version 2
<#
    .SYNOPSIS
    Name: Invoke-WindowsAudit.ps1
    Invokes an audit of the specified computers
    
    .DESCRIPTION
    This script is a thin wrapper to provide ease of use for the sub scripts
    in this solution. When executed; this will begin the gathering phase and
    collect all the data defined in the Audit-ScriptBlock, and serialise this
    data to disk for further reparsing in the future without having to run
    the gathering phase again.
    
    After the gathering phase is completed, if the -Compile switch is specified
    the script will then invoke a compliation of that data into an excel 
    spreadsheet using the supplied filter name. An example filter has been 
    provided; '.\Filters\Example.ps1'.

    .PARAMETER InputFile [String]
    The path to a Pipe Separated Values file which will be parsed for target information
    on what instances to harvest audit data from. The Per-line format should be:

        (hostname|ip):(port)|(protocol) 

    There is an example of what this file should look like in the .\Input directory
    of this solution.

    .PARAMETER Computers [String[]]
    String array of computers to run this script on. Defaults to this computer
    if not specified. If the computer value is a [host:port] or [ip:port] combination
    the specified port will be used for WinRM (Only).

    .PARAMETER Protocol [String: WinRM,PSExec]
    The protocol to use for the target computers specified in the $Computers parameter.
    Defaults to WinRM if not specified.

    .PARAMETER PSCredential [PSCredential]
    PSCredential that will be used for WinRM communications. Must be valid on the machines 
    you're trying to connect to, defaults to the current user context.

    .PARAMETER SerialisationDepth [Int: 2..8]
    Override value for the serialisation depth to use when this script is using the 
    System.Management.Automation.PSSerializer class. Defaults to 5, and range is limited
    to 2..8 as anything less than 2 is useless, anything greater than 8 will generate a very
    large (multi-gb) file and probably crash the targeted machine. Tweak only if the data 
    you want is nested so low in the dataset it's not being enumerated in the output.

    .PARAMETER Compile [Switch]
    This switch when present tells the script to do a compilation of the data to an Excel
    spreadsheet. If this is supplied; the -Filter parameter must be set.

    .PARAMETER Filter [String]
    The name of the filter you wish to apply to the dataset. Must exist in the .\Filters 
    directory with a .ps1 file extension.

    .EXAMPLE
    .\Invoke-WindowsAudit.ps1 `
            -InputFile ".\Input\MyComputerList.psv" `
            -PSCredential $MyPSCredential `
            -Compile `
            -Filter "Example";

    This will invoke an audit data gathering on the computers specified in the MyComputerList.psv
    file, using the $MyPSCredential credential over machines targeted with WinRM, will then
    compile the data into an Excel spreadsheet using the Example filter.

    .EXAMPLE
    .\Invoke-WindowsAudit.ps1 `
            -Computers "dev-test-01","dev-test-02" `
            -Protocol PSExec;

    This will invoke an audit data gathering on the computers specified in the Computers
    parameter using the PSExec protocol. No further processing will take place after the data
    has been gathered.

#>

[CmdletBinding()]
Param(
    # Path to a PSV file containing the list of computers|protocols to connect to
    [Parameter(Mandatory=$False)]
    [ValidateScript({$(Test-Path $_)})]
    [String]$InputFile,

    # String[] of computers to execute this script on
    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String[]]$Computers,

    # Protocol to use for connecting to the target machine
    [Parameter(Mandatory=$False)]
    [ValidateSet("WinRM","PSExec")]
    [String]$Protocol = "WinRM",

    # PSCredential that will be used for WinRM to connect to the target machines
    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [PSCredential]$PSCredential,

    # Override for the ExportDepth to CLI XML
    [Parameter(Mandatory=$False)]
    [ValidateRange(2,8)]
    [Int]$SerialisationDepth = 5,

    # This switch tells the script to compile the data once gathered
    [Parameter(Mandatory=$False)]
    [Switch]$Compile,

    # The filter to apply to the dataset
    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String]$Filter
)

# let's build our parameter set based on what has been supplied
$GatheringParameterSet = @();
$ScriptPath = ".\Scripts\Get-WindowsAuditData.ps1";

if ($InputFile) {
    $GatheringParameterSet += "-InputFile '$InputFile'";
}
if ($Computers) {
    $GatheringParameterSet += "-Computers '$Computers'";
}
if ($Protocol) {
    $GatheringParameterSet += "-Computers '$Protocol'";
}
if ($PSCredential) {
    $GatheringParameterSet += "-PSCredential '$PSCredential'";
}
if ($SerialisationDepth) {
    $GatheringParameterSet += "-SerialisationDepth '$SerialisationDepth'";
}

# And build the gathering command we want to execute
$GatheringCommand = $ScriptPath + $($GatheringParameterSet -Join " ");

# And execute the command
Invoke-Expression $GatheringCommand;

# Generate the excel sheets using the example filter if required
if ($Compile.IsPresent) {
    .\Scripts\Compile-WindowsAuditData.ps1 -Filter $Filter;
}

# Fin
Exit;