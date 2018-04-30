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

    # The machine identifier
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String]$MachineIdentifier
)

# Set EAP
$ErrorActionPreference = "Stop";

# Get our registry provider instance and authenticate against the target
$RegProvider = Get-WmiObject -ComputerName $Target -Credential $Credential -List "StdRegProv" -Namespace "root\default";

# Declare some registry helper variables
$HKLM = [UInt32]"0x80000002";
$FKey = "SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
$DomainProfile   = "$FKey\DomainProfile";
$PublicProfile   = "$FKey\PublicProfile";
$StandardProfile = "$FKey\StandardProfile";
$DomainLogPath   = "$DomainProfile\Logging";
$PublicLogPath   = "$PublicProfile\Logging";
$StandardLogPath = "$StandardProfile\Logging";
$FirewallKeys = @(
    "SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
    "SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules"
)

# Define a protocol map we can refer back to
$Protocols = @{ 
    1   = "ICMPv4";
    2   = "IGMP";
    6   = "TCP";
    17  = "UDP";
    41  = "IPv6";
    43  = "IPv6Route";
    44  = "IPv6Frag";
    47  = "GRE";
    58  = "ICMPv6";
    59  = "IPv6NoNxt";
    60  = "IPv6Opts";
    112 = "VRRP";
    113 = "PGM";
    115 = "L2TP";
} 

# Define an output variable
$Rules = @();

# Enumerate the firewall keys and get the goodies
$FirewallKeys.ForEach({

    # Grab the firewall key from the pipeline
    $FirewallKey = $_;

    # Try and grab the firewall rule keys from the parent
    try {
        $FirewallRules = $RegProvider.EnumValues($HKLM,$FirewallKey);

        # Enumerate the values and process them using a for loop for indexing
        for ($I = 0; $I -le $FirewallRules.Types.Count; $I++) {

            # Get the rule
            $Rule = ($RegProvider.GetStringValue($HKLM,$FirewallKey,$FirewallRules.sNames[$I])).sValue;

            # Get a PSCustomObject together to hold our output
            $Properties = New-Object PSCustomObject -Property @{
                NameOfRule  = $($FirewallRules.sNames[$I]);
                RuleVersion = $($Rule -split '\|')[0];
                RuleType    = $Null;
                Action      = $Null; 
                Active      = $Null;
                Dir         = $Null;
                Proto       = $Null;
                LPort       = $Null;
                App         = $Null;
                Name        = $Null;
                Desc        = $Null;
                EmbedCtxt   = $Null;
                Profile     = "All";
                RA4         = $Null;
                RA6         = $Null;
                Svc         = $Null;
                RPort       = $Null;
                ICMP6       = $Null;
                Edge        = $Null;
                LA4         = $Null;
                LA6         = $Null;
                ICMP4       = $Null;
                LPort2_10   = $Null;
                RPort2_10   = $Null;
            }

            # Work out if local or GPO rule
            if ($FirewallKey -match "System\\CurrentControlSet") {
                $Properties.RuleType = "Local";
            } else {
                $Properties.RuleType = "GPO";
            }

            # Enumerate the rule properties and get what we're after
            @($Rule -split "\|").ForEach({
            
                # Split the pipelined rule into key:value pairs
                $FirewallRule = $_ -split "=";

                # Switch on the result and set properties accordingly
                Switch($FirewallRule[0]) {
                    "Action"    {$Properties.Action     = $FirewallRule[1]};
                    "Active"    {$Properties.Active     = $FirewallRule[1]};
                    "Dir"       {$Properties.Dir        = $FirewallRule[1]};
                    "Protocol"  {$Properties.Proto      = $Protocols[[Int]($FirewallRule[1])]};
                    "LPort"     {$Properties.LPort      = $FirewallRule[1]};
                    "App"       {$Properties.App        = $FirewallRule[1]};
                    "Name"      {$Properties.Name       = $FirewallRule[1]};
                    "Desc"      {$Properties.Desc       = $FirewallRule[1]};
                    "EmbedCtxt" {$Properties.EmbedCtxt  = $FirewallRule[1]};
                    "Profile"   {$Properties.Profile    = $FirewallRule[1]};
                    "RA4"       {[Array]$Properties.RA4 += $FirewallRule[1]};
                    "RA6"       {[Array]$Properties.RA6 += $FirewallRule[1]};
                    "Svc"       {$Properties.Svc        = $FirewallRule[1]};
                    "RPort"     {$Properties.RPort      = $FirewallRule[1]};
                    "ICMP6"     {$Properties.ICMP6      = $FirewallRule[1]};
                    "Edge"      {$Properties.Edge       = $FirewallRule[1]};
                    "LA4"       {[Array]$Properties.LA4 += $FirewallRule[1]};
                    "LA6"       {[Array]$Properties.LA6 += $FirewallRule[1]};
                    "ICMP4"     {$Properties.ICMP4      = $FirewallRule[1]};
                    "LPort2_10" {$Properties.LPort2_10  = $FirewallRule[1]};
                    "RPort2_10" {$Properties.RPort2_10  = $FirewallRule[1]};
                }

                # Set the firewall rule name
                if ($Properties.Name -match "\@") { 
                    $Properties.Name = $Properties.NameOfRule;
                } 
            });

            # Add our firewall rule to the rules list
            $Rules += $Properties;
        }
    } catch {
        # Meh, both of these paths don't always exist
    }
});

# Get the firewall zone status
$DomainEnabled   = [Bool]($RegProvider.GetDwordValue($HKLM, $DomainProfile, "EnableFirewall")).uValue;
$PublicEnabled   = [Bool]($RegProvider.GetDwordValue($HKLM, $PublicProfile, "EnableFirewall")).uValue;
$StandardEnabled = [Bool]($RegProvider.GetDwordValue($HKLM, $StandardProfile, "EnableFirewall")).uValue;
              
# And return our output object
return  $([PSCustomObject][Ordered]@{
    MachineIdentifier       = $MachineIdentifier;
    Enabled                 = $(@($DomainEnabled,$PublicEnabled,$StandardEnabled) -Contains $True);
    DomainProfileEnabled    = $DomainEnabled;
    DomainProfileLogPath    = [String]($RegProvider.GetStringValue($HKLM,$DomainLogPath,"LogFilePath").sValue);
    DomainProfileLogSize    = [Int]($RegProvider.GetDWORDValue($HKLM,$DomainLogPath,"LogFileSize").uValue);
    PublicProfileEnabled    = $PublicEnabled;
    PublicProfileLogPath    = [String]($RegProvider.GetStringValue($HKLM,$PublicLogPath,"LogFilePath").sValue);
    PublicProfileLogSize    = [Int]($RegProvider.GetDWORDValue($HKLM,$PublicLogPath,"LogFileSize").uValue);
    StandardProfileEnabled  = $StandardEnabled;
    StandardProfileLogPath  = [String]($RegProvider.GetStringValue($HKLM,$StandardLogPath,"LogFilePath").sValue);
    StandardProfileLogSize  = [Int]($RegProvider.GetDWORDValue($HKLM,$StandardLogPath,"LogFileSize").uValue);
    Rules                   = $Rules;
});