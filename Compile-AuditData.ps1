[Cmdletbinding(DefaultParameterSetName='Excel')]
Param(
    # Compile using Excel or SQL
    [Parameter(Mandatory=$True)]
    [Parameter(ParameterSetName="Excel")]
    [Parameter(ParameterSetName="SQL")]
    [ValidateSet("Excel","SQL")]
    [String]$CompilationType,

    # The name of the filter to use when compiling
    [Parameter(Mandatory=$True)]
    [Parameter(ParameterSetName="Excel")]
    [Parameter(ParameterSetName="SQL")]
    [ValidateNotNullOrEmpty()]
    [String]$Filter,

    # SQL Server\instance name
    [Parameter(Mandatory=$True,ParameterSetName="SQL")]
    [ValidateNotNullOrEmpty()]
    [String]$SQLServerName,

    # SQL database name
    [Parameter(Mandatory=$True,ParameterSetName="SQL")]
    [ValidateNotNullOrEmpty()]
    [String]$SQDatabaseName
)

#---------[ Global Declarations ]---------

# EAP to stop so we can trap errors in catch blocks
$ErrorActionPreference = "Stop";

# Trigger so we know something went wrong during the process
$WarningTrigger = $False;

#---------[ Imports ]---------

# Bring in our functions library
try {
    Write-Host "Importing Audit module: " -ForegroundColor Yellow -NoNewline;
    Import-Module ".\Lib\Audit\Audit-Functions.psm1" -DisableNameChecking -Force;
    Write-Host "Succeeded." -ForegroundColor Green;
}
catch {
    # Can't use Write-ShellMessage here
    $Message = "There was a problem attempting to import the Audit module: $($_.Exception.Message)";
    Write-Host $Message -ForegroundColor Red;
    Exit(1);
}

#---------[ Extended Validation ]---------

# Test whether the filter exists and get the path
try {
    $FilterPath = ".\Filters\{0}-{1}.ps1" -F $Filter,$CompilationType;
    if (!(Test-Path $FilterPath)) {
        throw [System.IO.FileNotFoundException] "The file '$FilterPath' does not exist";
    }
}
catch {
    Write-ShellMessage -Message "There was a problem validating the selected filter" -Type ERROR -ErrorRecord $_;
    Exit(1);
}

#---------[ Main() ]---------

# Get a list of the CLI XML files to process
try {
    Write-ShellMessage -Message "Getting list of CLI XML files to process" -Type INFO;
    $CliXmlFilesToProcess = Get-ChildItem ".\Output\*.xml";
}
catch {
    Write-ShellMessage -Message "There was a problem getting the list of CLI XML files to process" -Type ERROR -ErrorRecord $_;
    Exit(1);
}

# Declare a ticker and start time so we can estimate how long the operation will take
$Ticker    = 0;
$StartTime = Get-Date

# Enumerate the collection
$CliXmlFilesToProcess | %{
    # Increment the ticker so we know how many we've processed so far
    $Ticker++;

    # Get the filename and let the user know what we're doing
    $FileName = $_.Name;
    Write-ShellMessage -Message "Processing file '$FileName'" -Type INFO;

    # Get the CLI XML back into a PSCustomObject
    $HostInformation = Import-Clixml -Path $_.FullName;
    
    # Swiffy based on the compilation type to call the correct filter with params
    Switch($CompilationType) {
        "Excel" {
            & $FilterPath -HostInformation $HostInformation;
        }
        "SQL" {
            & $FilterPath -HostInformation $HostInformation -SQLServerName $SQLServerName -SQLDatabaseName $SQLDatabaseName;
        }
    }

    # Work out remaining time
    $SecondsElapsed   = ((Get-Date) - $StartTime).TotalSeconds;
    $SecondsRemaining = ($SecondsElapsed / ($Ticker / $CliXmlFilesToProcess.Count)) - $SecondsElapsed;

    # Write progress so we can see the top level info
    $ProgressParams = @{
        ID                 = 10;
        Activity           = "Compiling audit results";
        Status             = "Compiled $Ticker files out of $($CliXmlFilesToProcess.Count)";
        PercentComplete    = ($Ticker / $CliXmlFilesToProcess.Count) * 100;
        SecondsRemaining   = $SecondsRemaining;
    }
    Write-Progress @ProgressParams;
}

#---------[ Fin ]---------
Exit;