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
    The path to a file which will be parsed for target information on which 
    instances to harvest audit data from. One computer name or IP address per
    line.

    .PARAMETER Computers [String[]]
    String array of computers to run this script on. Used mutually exclusively
    with InputFile as a shell-method of supplying instances to target.

    .PARAMETER PSCredential [PSCredential]
    PSCredential that will be used for WinRM communications. Must be valid on 
    the machines you're trying to connect to, defaults to the current user 
    identity.

    .PARAMETER CompileOnly [Switch]
    This switch when present tells the script to do a compilation of the data
    only, using cached information from a previous gathering run.

    .PARAMETER Compile [Switch]
    This switch when present tells the script to do a compilation of the data to 
    an Excel spreadsheet. If this is supplied; the `Filter` parameter _must also_ 
    be supplied.

    .PARAMETER Filter [String]
    The name of the filter you wish to apply to the dataset. Must exist in the 
    `.\Filters` directory with a `.ps1` file extension. An example filter has been 
    supplied with this solution with the name of `Example`.

    .EXAMPLE
    .\Invoke-WindowsAudit.ps1 `
            -InputFile ".\Input\MyComputerList.txt" `
            -PSCredential $MyPSCredential `
            -Compile `
            -Filter "Example";

    This will invoke an audit data gathering on the computers specified in the 
    MyComputerList.txt file using the $MyPSCredential credential, and then compile 
    the data into an Excel spreadsheet using the Example filter.

    .EXAMPLE
    .\Invoke-WindowsAudit.ps1 -Computers "dev-test-01","dev-test-02" -PSCredential $MyPSCredential;

    This will invoke an audit data gathering on the computers specified in the Computers
    parameter using the PSExec protocol. No further processing will take place after the data
    has been gathered.

    .EXAMPLE
    .\Invoke-WindowsAudit.ps1 -CompileOnly -Filter "Example";

    This will invoke a compilation of cached data using the supplied filter.
#>

[CmdletBinding(DefaultParameterSetName='InputFile')]
Param(
    # Path to a PSV file containing the list of computers|protocols to connect to
    [Parameter(Mandatory=$False,ParameterSetName="InputFile")]
    [ValidateScript({$(Test-Path $_)})]
    [String]$InputFile,

    # String[] of computers to execute this script on
    [Parameter(Mandatory=$False,ParameterSetName="ComputerList")]
    [ValidateNotNullOrEmpty()]
    [String[]]$Computers,

    # PSCredential that will be used for WinRM to connect to the target machines
    [Parameter(Mandatory=$True)]
    [Parameter(ParameterSetName="InputFile")]
    [Parameter(ParameterSetName="ComputerList")]
    [ValidateNotNullOrEmpty()]
    [PSCredential]$PSCredential,

    # This switch tells the script to only do the compile phase
    [Parameter(Mandatory=$False)]
    [Parameter(ParameterSetName="InputFile")]
    [Parameter(ParameterSetName="ComputerList")]
    [Switch]$CompileOnly,

    # This switch tells the script to compile the data once gathered
    [Parameter(Mandatory=$False)]
    [Parameter(ParameterSetName="InputFile")]
    [Parameter(ParameterSetName="ComputerList")]
    [Switch]$Compile,

    # The filter to apply to the dataset
    [Parameter(Mandatory=$False)]
    [Parameter(ParameterSetName="InputFile")]
    [Parameter(ParameterSetName="ComputerList")]
    [ValidateNotNullOrEmpty()]
    [String]$Filter
)

# Start transcript
$DateStamp = Get-Date -Format "ddMMyy_HHmmss";
$Transcriptfile = ".\Windows-Audit-Transcript-$env:username-$DateStamp.log";
[Void](Start-Transcript $Transcriptfile);

# Run the gather phase if required
if (!($CompileOnly.IsPresent)) {
    .\Scripts\Get-WindowsAuditData.ps1 `
                            -InputFile $InputFile `
                            -Computers $Computers `
                            -PSCredential $PSCredential;
}

# Run the compilation if required
if ($Compile.IsPresent -or $CompileOnly.IsPresent) {
    .\Scripts\Compile-WindowsAuditData.ps1 -Filter $Filter;
}

# Stop transcript
[Void](Stop-Transcript);

# Cleanup transcript
$TranscriptContent = Get-Content $TranscriptFile | Out-String;
$TranscriptContent = $TranscriptContent.Replace($($PSCredential.GetNetworkCredential().Password),"*****");
Set-Content -Path $Transcriptfile -Value $TranscriptContent;

# Fin
Exit;