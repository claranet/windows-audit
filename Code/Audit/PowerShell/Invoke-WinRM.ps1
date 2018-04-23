[Cmdletbinding()]
Param(
    # The server we're targetting
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String]$Target,

    # The credential we're using to connect
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [PSCredential]$Credential,

    # The script we're executing
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String]$ScriptPath,

    # The Machine identifer we'll tag the result with
    [Parameter(Mandatory=$True)]
    [ValidateScript({$_ -Match "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"})]
    [String]$MachineIdentifier,

    # Whether to use Ssl on the WinRM connection
    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [Switch]$UseSSL
)

# Set EAP
$ErrorActionPreference = "Stop";

# Work out what port we should use based on the TLS check
if ($UseSSL.IsPresent) {
    $Port = 5986;
} else {
    $Port = 5985;
}

# Bring in the script
$ScriptBlock = [ScriptBlock]::Create($(Get-Content $ScriptPath -Raw));

# Build the params
$WinRmParams = @{
    ComputerName = $Target;
    Credential = $Credential;
    ScriptBlock = $ScriptBlock;
    Port = $Port;
    UseSsl = $UseSSL.IsPresent;
    ArgumentList = $MachineIdentifier;
}

# Invoke the script supplying the params
$Result = Invoke-Command @WinRmParams;

# And return
return $Result;
