<#
    .SYNOPSIS
    Name: Compile-WindowsAuditData.ps1
    Parses the results from Get-WindowsAuditData.ps1
    
    .DESCRIPTION
    This script is a thin wrapper to provide ease of use for the filters in
    this solution. The filters provide a way to parse the same data repeatedly
    to create different views of the data, this will validate that the filter
    chosen is present and call the filter multiple times providing each file from
    the RawData directory.

    .EXAMPLE
    .\Parse-WindowsAuditData.ps1 -Filter Example
    This will parse the entire contents of the RawData directory, generating
    the output CSV files for compliation using the 'Example' filter.

    .TODO# Need to add error handling and output logging

    #requires -version 2
#>

[CmdletBinding()]
Param(
    # Path to a PSV file containing the list of computers|protocols to connect to
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String]$Filter
)

# Get the filter path
$FilterPath = ".\Filters\$Filter.ps1";

if (!(Test-Path $FilterPath)) {
    throw "Selected filter does not exist at '$FilterPath'";
    break;
}

# Get a list of the CLI XML files to process
$CliXmlFilesToProcess = Get-ChildItem ".\Output\RawData\*cli.xml";

# Enumerate the collection
$CliXmlFilesToProcess | %{
    # Get the CLI XML back into a PSCustomObject
    $HostInformation = Import-Clixml -Path $_.FullName;

    # And pass the result on to the correct filter for execution
    & $FilterPath -HostInformation $HostInformation;
}