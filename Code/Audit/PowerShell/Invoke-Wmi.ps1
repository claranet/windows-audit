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
    [String]$MachineIdentifier
)

# Set EAP
$ErrorActionPreference = "Stop";

# Invoke the script supplying the params
$Result = & $ScriptPath $Target $Credential $MachineIdentifier;

# And return
return $Result;
