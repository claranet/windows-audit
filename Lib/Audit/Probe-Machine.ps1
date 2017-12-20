[Cmdletbinding()]
Param(
    # The Node object we want to work with
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [PSCustomObject]$Node,

    # The PSCredential to check WinRM using
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [PSCredential]$PSCredential
)

# Set EAP
$ErrorActionPreference = "Stop";

# Let's check and see whether we've been given an IP or hostname
if ($Node.IPAddress) {
    $LookupMode   = "IP";
    $LookupTarget = $Node.IPAddress;
}
elseif ($Node.Hostname) {
    $LookupMode   = "HOST";
    $LookupTarget = $Node.Hostname;
}
else {
    throw "Target host has no IPAddress or Hostname (ID: $($Node.ID))";
}

# See if we can get ICMP traffic
For ($I = 0; $I -le 2; $I++) {
	try {
        # Init ping object
		$Ping = New-Object System.Net.NetworkInformation.Ping;				
		$Result = $Ping.Send($LookupTarget, 1000, $(New-Object Byte[] 32));
                
        # Test the result
		if($Result.Status -eq "Success") {
            # Success, no need for retry
			$ICMPStatus = "UP";
			break;
		}
		else {
            # Failure, will retry if not limit not exceeded
			$ICMPStatus = "DOWN";
		}
	}
	catch {
        # Something wrong here, false and break
		$ICMPStatus = "DOWN";
		break;
	}
};
             
# Try and get the missing host details
Switch ($LookupMode) {
    "IP" {
        try{ 
            $DNSName = [System.Net.Dns]::GetHostEntry($LookupTarget).HostName;
        } 
        catch { 
            $DNSName = "(No DNS entry for $LookupTarget)";
        }
    }
    "HOST" {
        try{ 
            # This may return multiples, select one of the IPv4 addresses
            $IPAddresses = [System.Net.DNS]::GetHostAddresses($LookupTarget).Where({$_.AddressFamily -ne "InterNetworkV6"});
            $IPAddress = ($IPAddresses | Sort Address -Descending | Select -First 1).IpAddressToString;
        } 
        catch { 
            $IPAddress = "(No IP entry found for $LookupTarget)";
        }
    }
}

# Get the MAC address if we can
$ArpIP = (. ({$Node.IPAddress},{$IPAddress})[$Node.IPAddress -eq $Null]);
if ($ArpIp -ne $Null) {
    ((Invoke-Expression "arp -a").ToUpper()).ForEach({
        if($_.TrimStart().StartsWith($ArpIP))
        {
            $MACAddress = [Regex]::Matches($_,"([0-9A-F][0-9A-F]-){5}([0-9A-F][0-9A-F])").Value;
        }
    });
}
else {
    $MACAddress = "Unknown";
}

# Test for WinRM connectivity
try {
    [Void](Test-WSMan -Computer $LookupTarget -Auth Negotiate -Cred $PSCredential);
    $WinRM = "OK";
}
catch {
    # Capture the error record from the pipeline
    $E = $_;

    # Variety of reasons here, try to enumerate them but fallthrough to exception text
    if ($E.Exception.Message.Contains("Access is denied.")) {
        $WinRM = "Access Denied [$($PSCredential.UserName)]";
    }
    elseif ($E.Exception.Message.Contains("Verify that the specified computer name is valid, that the computer is accessible")) {
        $WinRM = "Not Visible";
    }
    elseif ($E.Exception.Message.Contains("Verify that the service on the destination is running")) {
        $WinRM = "Not Available";
    }
    elseif ($E.Exception.Message.Contains("The WinRM client cannot process the request because the server name cannot be resolved")) {
        $WinRM = "Name Resolution Failure";
    }
    elseif ($E.Exception.Message -match "received an HTTP server error status \(\d{3}\)") {
        $HTTPCode = [Regex]::Match($E.Exception.Message,'(received an HTTP server error status \()(\d{3})(\))').Groups[2].Value;
        $WinRM = "Broken [$HTTPCode]";
    }
    else {
        $WinRM = $E.Exception.Message;
    }
}

# Set the node's missing properties dependent on lookup mode
Switch ($LookupMode) {
    "IP" {
        $Node.Hostname = $DNSName;
    }
    "HOST" {
        $Node.IPAddress = $IPAddress;
    }
}

# Build the status string
$Status = $(if (($ICMPStatus -eq "UP") -or ($WinRM -eq "OK")) {"Passed"} else {"Failed"});
$StatusString = [String]::Format("[{0}][Network Check {1}] WinRM: {2}; ICMP: {3}`r`n",$(Get-Date -f "dd/MM/yy HH:mm:ss"),$Status,$WinRM,$ICMPStatus);

# Update the rest of the node information with what we gathered
$Node.Status       = $StatusString;
$Node.ICMPStatus   = $ICMPStatus;
$Node.MACAddress   = $MACAddress;
$Node.BufferSize   = $Result.Buffer.Length;
$Node.ResponseTime = $Result.RoundtripTime;
$Node.TTL          = $Result.Options.Ttl;
$Node.WinRMStatus  = $WinRM;

# And return the node
return $Node;