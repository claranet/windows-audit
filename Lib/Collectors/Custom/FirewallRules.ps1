[CmdletBinding()]
Param(
    # Guid for matching back to the correc machine
    [Parameter(Mandatory=$True)]
    [ValidateScript({$_ -Match "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"})]
    [String]$ID
)

# Set EAP
$ErrorActionPreference = "Stop";

# Get our return array sorted
$NetshFirewallRules = @();

# Quick check make sure the firewall is on
if (@((Get-Service | ?{$_.DisplayName -like "*Firewall*"}).Status) -contains "Running") {

    # Get a new hash in place so we can add values easily
    $Hash = @{
        MachineIdentifier = $ID;
        Name              = $Null;
        Enabled           = $Null;
        Direction         = $Null;
        Profiles          = $Null;
        Grouping          = $Null;
        LocalAddresses    = $Null;
        RemoteAddresses   = $Null;
        Protocol          = $Null;
        LocalPorts        = $Null;
        RemotePorts       = $Null;
        EdgeTraversal     = $Null;
    };
                
    # Firewall rules using Netsh as this is the most compatible option
    ForEach ($Rule in $(netsh advfirewall firewall show rule name="all")) {

        # If the line isn't a separator, parse and add
        if ($Rule -notmatch "----------------------------------------------------------------------"){
            switch -Regex ($Rule){
                '^Rule Name:\s+(?<RuleName>.*$)'   {$Hash.Name            = $Matches.RuleName;Break}
                '^Enabled:\s+(?<Enabled>.*$)'      {$Hash.Enabled         = $Matches.Enabled;Break}
                '^Direction:\s+(?<Direction>.*$)'  {$Hash.Direction       = $Matches.Direction;Break}
                '^Profiles:\s+(?<Profiles>.*$)'    {$Hash.Profiles        = $Matches.Profiles;Break}
                '^Grouping:\s+(?<Grouping>.*$)'    {$Hash.Grouping        = $Matches.Grouping;Break}
                '^LocalIP:\s+(?<LocalIP>.*$)'      {$Hash.LocalAddresses  = $Matches.LocalIP;Break}
                '^RemoteIP:\s+(?<RemoteIP>.*$)'    {$Hash.RemoteAddresses = $Matches.RemoteIP;Break}
                '^Protocol:\s+(?<Protocol>.*$)'    {$Hash.Protocol        = $Matches.Protocol;Break}
                '^LocalPort:\s+(?<LocalPort>.*$)'  {$Hash.LocalPorts      = $Matches.LocalPort;Break}
                '^RemotePort:\s+(?<RemotePort>.*$)'{$Hash.RemotePorts     = $Matches.RemotePort;Break}
                '^Edge traversal:\s+(?<Edge_traversal>.*$)' {
                    $Hash.EdgeTraversal = $Matches.Edge_traversal;
                    $NetshFirewallRules += $(New-Object PSCustomObject -Property $Hash);
                    Break;
                }
            }
        }
    };
}

# Return the goods
return ,$NetshFirewallRules;