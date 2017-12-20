[CmdletBinding()]
Param(
    # Guid for matching back to the correc machine
    [Parameter(Mandatory=$True)]
    [ValidateScript({$_ -Match "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"})]
    [String]$ID
)

# Set EAP
$ErrorActionPreference = "Stop";

# Ok get a full netstat and declare an output object
$Netstat = Invoke-Expression "netstat -ano"
$ConnectionInformation = @();

# Enumerate the output from netstat
$Netstat | ?{$_.Contains("ESTABLISHED") -or $_.Contains("CLOSE_WAIT")} | %{

    # Ok get the netstat row into an object to process
    $Connection = $_;

    # Split up on and dedupe spaces
    $Properties = $Connection.Split(" ") | ?{$_};

    # Get the process object from the PID
    $ProcessObject = Get-Process -ID $Properties[4] -ErrorAction SilentlyContinue;

    # Let's split out some advanced properties here, as IPv6 addresses are a bit different
    if ($Properties[1].Contains("[")) {
        # Ok this is an IPv6 address, can't straight parse
        $LocalAddress  = [Regex]::Match($Properties[1],'(?<=\[).+?(?=\])').Value;
        $LocalPort     = $Properties[1].Replace($LocalAddress,"").Split(":")[1];
        $RemoteAddress = [Regex]::Match($Properties[2],'(?<=\[).+?(?=\])').Value;
        $RemotePort    = $Properties[2].Replace($RemoteAddress,"").Split(":")[1];
    }
    else {
        # This is IPv4, can safely be split on the semi
        $LocalAddress  = $Properties[1].Split(":")[0];
        $LocalPort     = $Properties[1].Split(":")[1];
        $RemoteAddress = $Properties[2].Split(":")[0];
        $RemotePort    = $Properties[2].Split(":")[1];
    }

    # Create a new PSCustomObject using the properties we just split out, add to the collection
    $ConnectionInformation += $(New-Object PSCustomObject -Property @{
        MachineIdentifier  = $ID;
        Protocol           = $Properties[0];
        LocalAddress       = $LocalAddress;
        LocalPort          = $LocalPort;
        RemoteAddress      = $RemoteAddress;
        RemotePort         = $RemotePort;
        State              = $Properties[3];
        ProcessID          = $Properties[4];
        ProcessName        = $ProcessObject.Name;
        ProcessDescription = $ProcessObject.Description;
        ProcessProduct     = $ProcessObject.Product;
        ProcessFileVersion = $ProcessObject.FileVersion;
        ProcessExePath     = $ProcessObject.Path;
        ProcessCompany     = $ProcessObject.Company;
    });
}

# And return
return ,$ConnectionInformation;