[Cmdletbinding()]
Param(
    # The server we're targetting
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String]$Target,

    # Username we'll use to connect
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String]$Username,

    # Password we'll use to connect
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String]$Password,

    # The modifier we'll add to the end of the folder
    [Parameter(Mandatory=$True)]
    [ValidateSet("LessThan","GreaterThan","EqualTo","GreaterThanOrEqualTo","LessThanOrEqualTo")]
    [String]$Modifier
)

# Check if we have plink installed
Write-Host "Checking for putty/plink install status" -ForegroundColor Yellow;
if (!(Get-Command "plink" -ErrorAction SilentlyContinue)) {
    Write-Error "Sorry it appears you don't have Putty/Plink installed - please use choco install putty before running this.";
    Exit(1);
}

# Set EAP and get current directory
$ErrorActionPreference = "Stop";
$CurrentDirectory = $PSScriptRoot;

# Bring in the utils module
Write-Host "Importing utils module" -ForegroundColor Yellow;
Import-Module "$CurrentDirectory\Utility.psm1" -Force -DisableNameChecking;

# Get the connection info from the target
Write-Host "Obtaining target distro information" -ForegroundColor Yellow;
$Params = @{
    Target            = $Target;
    Username          = $Username;
    Password          = $Password;
    ScriptPath        = "$CurrentDirectory\Collectors\SSH\_ConnectionCheck.sh";
    MachineIdentifier = [Guid]::NewGuid().Guid;
    AcceptHostKey     = $True;
}
$Result = Invoke-SSH @Params;

# Create the folder based on our target data
Write-Host "Creating semantic scripting folder" -ForegroundColor Yellow;
$Distro   = $Result.DISTRIB_ID.ToLower();
$Version  = $Result.VERSION_ID;
$Operator = $(Switch($Modifier){
    "LessThan"             {"-"}
    "GreaterThan"          {"+"}
    "EqualTo"              {"="}
    "GreaterThanOrEqualTo" {"+="}
    "LessThanOrEqualTo"    {"-="}
});

$FolderName = "{0}#{1}#{2}" -f $Distro,$Version,$Operator;
$Folder = New-Item "$CurrentDirectory\Collectors\SSH\$FolderName" -ItemType Directory;

# Done
Write-Host "Created semantic folder for distribution '$Distro' of version '$Version' with '$Operator' operator at path: '$($Folder.Fullname)'" -ForegroundColor Green;