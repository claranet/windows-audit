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
$NetshFirewallConfiguration = @();

# Quick check make sure the firewall is on
if (@((Get-Service | ?{$_.DisplayName -like "*Firewall*"}).Status) -contains "Running") {

    # Grab the netsh output to a string
    $NetshOutput = Invoke-Expression "netsh advfirewall show allprofiles" | Out-String;
            
    # Split up into sections based on the page break
    $Blocksplit = $NetshOutput -split "----------------------------------------------------------------------";

    # Now we can define our blocks ready for parsing
    $DomainProfileBlock  = $Blocksplit[1].Split("`r`n") | ?{
        ![String]::IsNullOrEmpty($_) -and $_ -notlike "*:*" -and $_ -notlike "LocalFirewallRules*" -and $_ -notlike "LocalConSecRules*" -and $_ -ne "Ok.";
    };
    $PrivateProfileBlock = $Blocksplit[2].Split("`r`n") | ?{
        ![String]::IsNullOrEmpty($_) -and $_ -notlike "*:*" -and $_ -notlike "LocalFirewallRules*" -and $_ -notlike "LocalConSecRules*" -and $_ -ne "Ok.";
    };
    $PublicProfileBlock  = $Blocksplit[3].Split("`r`n") | ?{
        ![String]::IsNullOrEmpty($_) -and $_ -notlike "*:*" -and $_ -notlike "LocalFirewallRules*" -and $_ -notlike "LocalConSecRules*" -and $_ -ne "Ok.";
    };

    # Parse out the domain block
    $DomainProfileHash = @{
        MachineIdentifier = $ID;
        ProfileName       = "Public";
    };
    $DomainProfileBlock | %{
        # Ok let's split up the row and add the values to our hashtable
        $Split = $_.Split(" ") | ?{$_};
        $DomainProfileHash.$($Split[0]) = $Split[1];
    }
    $NetshFirewallConfiguration += New-Object PSCustomObject -Property $DomainProfileHash;

    # Parse out the private block
    $PrivateProfileHash = @{
        MachineIdentifier = $ID;
        ProfileName       = "Public";
    };
    $PrivateProfileBlock | %{
        # Ok let's split up the row and add the values to our hashtable
        $Split = $_.Split(" ") | ?{$_};
        $PrivateProfileHash.$($Split[0]) = $Split[1];
    }
    $NetshFirewallConfiguration += New-Object PSCustomObject -Property $PrivateProfileHash;

    # Parse out the Public block
    $PublicProfileHash = @{
        MachineIdentifier = $ID;
        ProfileName       = "Public";
    };
    $PublicProfileBlock | %{
        # Ok let's split up the row and add the values to our hashtable
        $Split = $_.Split(" ") | ?{$_};
        $PublicProfileHash.$($Split[0]) = $Split[1];
    }
    $NetshFirewallConfiguration += New-Object PSCustomObject -Property $PublicProfileHash;
}
else {
    # Ok firewall service isn't running, let's inject some values manually
    "Domain","Public","Private" | %{
        $NetshFirewallConfiguration += $(New-Object PSCustomObject -Property @{
            MachineIdentifier          = $ID;
            ProfileName                =  $_;
            FileName                   = $Null;
            UnicastResponseToMulticast = $Null;
            RemoteManagement           = $Null;
            LogAllowedConnections      = $Null;
            LogDroppedConnections      = $Null;
            State                      = "Off";
            Firewall                   = $Null;
            InboundUserNotification    = $Null;
            MaxFileSize                = $Null;
        });
    }
}

# Return the goods
return ,$NetshFirewallConfiguration;