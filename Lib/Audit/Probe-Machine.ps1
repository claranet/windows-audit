[Cmdletbinding()]
Param(
    # The target we want to scan
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String]$Target,

    # PSCredential for accesing Windows hosts
    [Parameter(Mandatory=$False)]
    [PSCredential]$WindowsCredential,

    # Username for accessing Linux hosts
    [Parameter(Mandatory=$False)]
    [String]$LinuxUsername,

    # Password for accessing Linux hosts
    [Parameter(Mandatory=$False)]
    [String]$LinuxPassword,

    # Path to the private key file for Linux hosts
    [Parameter(Mandatory=$False)]
    [String]$LinuxPrivateKeyFile,

    # Path to the private key file for Linux hosts
    [Parameter(Mandatory=$False)]
    [String]$LinuxPrivateKeyPassphrase
)

# Set E|P|W prefs and start time
$ErrorActionPreference = "Stop";
$ProgressPreference = "SilentlyContinue";
$WarningPreference = "SilentlyContinue";
$StartTime = Get-Date;

# Build an object now so we can set properties easily
$Result = [PSCustomObject][Ordered]@{
    Target        = $Target;
    ScanInfo = [PSCustomObject][Ordered]@{
        OS = $Null;
        TimeTaken = $Null;
        Credentials = [PSCustomObject][Ordered]@{
            Windows = $WindowsCredential;
            Linux = [PSCustomObject][Ordered]@{
                Username = $LinuxUsername;
                Password = $LinuxPassword;
                PrivateKeyFile = $LinuxPrivateKeyFile;
                PrivateKeyPassphrase = $LinuxPrivateKeyPassphrase;
            };
        };
    };
    Networking = [PSCustomObject][Ordered]@{
        ICMP = $Null;
        ResponseTime = $Null;
        HostNames = $(New-Object System.Collections.ArrayList);
        DnsAliases = $(New-Object System.Collections.ArrayList);
        IPv4Addresses = $(New-Object System.Collections.ArrayList);
        IPv6Addresses = $(New-Object System.Collections.ArrayList);
    };
    RemoteConnection = [PSCustomObject][Ordered]@{
        Healthy = $Null;
        WinRm = [PSCustomObject][Ordered]@{
            Success = $Null;
            Error = $Null;
            UseTls = $Null;
        };
        Wmi = [PSCustomObject][Ordered]@{
            Success = $Null;
            Error = $Null;
        };
        Ssh = [PSCustomObject][Ordered]@{
            Success = $Null;
            Error = $Null;
            UseCredentials = $Null;
            UsePrivateKey = $Null;
            UsePrivateKeyPassphrase = $Null;
        };
    };
};

# Test for ICMP ping first
try {
    # Init ping object and hit it
    $Ping       = New-Object System.Net.NetworkInformation.Ping;
    $PingResult = $Ping.Send($Target, 1000, $(New-Object Byte[] 32));
                
    # Test the result
    if($PingResult.Status -eq "Success") {

        # Set our ICMP status
        $Result.Networking.ICMP = $True;
        
        # Check for TypeOf property and set the response time
        if ($PingResult.ResponseTime) {
            $Result.Networking.ResponseTime = $PingResult.ResponseTime;
        } else {
            $Result.Networking.ResponseTime = $PingResult.RoundtripTime;
        }
    } else {
        # Failed
        $Result.ICMP = $False;
    }
}
catch {
    # Total failure
    $Result.ICMP = $False;
}

# Declare an array to hold our resolving targets
$Targets = New-Object System.Collections.ArrayList;

# Init a loop controller and seed our resolvers array
$Resolving = $True;
[Void]($Targets.Add($([PSCustomObject]@{
    Target   = $Target;
    Resolved = $False;
})));

# Recursive resolution until we find all the possible entries
While($Resolving) {

    # Build some current counters
    $HostNamesCounter     = $Result.Networking.HostNames.Count;
    $DnsAliasesCounter    = $Result.Networking.DnsAliases.Count;
    $Ipv4AddressesCounter = $Result.Networking.Ipv4Addresses.Count;
    $Ipv6AddressesCounter = $Result.Networking.Ipv6Addresses.Count;
    $TargetsCounter       = $Targets.Count;

    # Resolve all the current targets we have
    try {
        $ResolvedTargets = $($Targets.Where({!$_.Resolved}) | %{
            [System.Net.DNS]::GetHostEntry($_.Target);           
        });
    } catch {
        # If we've failed to resolve anything, break
        $Resolving = $False; Break;
    };

    # Update the targets collection now we're not using it
    $Targets | %{$_.Resolved = $True};

    # Process the results we've gathered
    $ResolvedTargets | %{

        # Grab the resolved target from the pipeline
        $ResolvedTarget = $_;
        
        # Add the primary DNS name to the store if !exists
        if (!($Result.Networking.DnsAliases.Contains($ResolvedTarget.HostName.ToLower()))) {
            [Void]($Result.Networking.DnsAliases.Add($ResolvedTarget.HostName.ToLower()));
        }

        # Add the primary DNS name to the targets if !exists
        if (!($Targets.Where({$_.Target -eq $ResolvedTarget.HostName}))) {
            
            [Void]($Targets.Add($([PSCustomObject]@{
                Target   = $ResolvedTarget.HostName;
                Resolved = $False;
            })));
        }

        # Split out the hostname from the DNS name
        $Hostname = $ResolvedTarget.HostName -split "\." | Select -First 1;

        # Add the hostname to the store if !exists
        if (!($Result.Networking.HostNames.Contains($Hostname.ToUpper()))) {
            [Void]($Result.Networking.HostNames.Add($Hostname.ToUpper()));
        }

        # Add the hostname to the targets if !exists
        if (!($Targets.Where({$_.Target -eq $Hostname}))) {
            [Void]($Targets.Add($([PSCustomObject]@{
                Target   = $Hostname;
                Resolved = $False;
            })));
        }

        # For each of the DNS aliases, add to the store/targets if !exists
        $ResolvedTarget.Aliases | %{
            
            # Grab the alias from the pipeline
            $Alias = $_;

            # DNS entries
            if (!($Result.Networking.DnsAliases.Contains($Alias.ToLower()))) {
                [Void]($Result.Networking.DnsAliases.Add($Alias.ToLower()));
            }
            
            # Targets
            if (!($Targets.Where({$_.Target -eq $Alias}))) {
                [Void]($Targets.Add($([PSCustomObject]@{
                    Target   = $Alias;
                    Resolved = $False;
                })));
            }
        }

        # For each of the IP addresses, add to the store/targets if !exists
        $ResolvedTarget.AddressList | %{
            
            # Grab the IP from the pipeline
            $IP = $_.IPAddressToString;

            # IP Addresses
            if ($IP -match "^\d+.\d+.\d+.\d+$") {
                if (!($Result.Networking.Ipv4Addresses.Contains($IP))) {
                    [Void]($Result.Networking.Ipv4Addresses.Add($IP));
                }
            } else {
                if (!($Result.Networking.Ipv6Addresses.Contains($IP))) {
                    [Void]($Result.Networking.Ipv6Addresses.Add($IP));
                }
            }

            # Targets
            if (!($Targets.Where({$_.Target -eq $IP}))) {
                [Void]($Targets.Add($([PSCustomObject]@{
                    Target   = $IP;
                    Resolved = $False;
                })));
            }
        }

    }

    # Check the counts based on what we gathered at the start
    $FoundHostNames     = $Result.Networking.HostNames.Count - $HostNamesCounter;
    $FoundDnsAliases    = $Result.Networking.DnsAliases.Count - $DnsAliasesCounter;
    $FoundIpv4Addresses = $Result.Networking.Ipv4Addresses.Count - $Ipv4AddressesCounter;
    $FoundIpv6Addresses = $Result.Networking.Ipv6Addresses.Count - $Ipv6AddressesCounter;
    $FoundTargets       = $Targets.Count - $TargetsCounter;

    # If none of our counters have incremented, break
    if (($FoundHostNames + $FoundDnsAliases + $FoundIpv4Addresses + $FoundIpv6Addresses + $FoundTargets) -eq 0) {
        $Resolving = $False; Break;
    }
}

# Try and get the target's OS
try {
    # Do the nmap scan
    $Nmap = Invoke-Expression "nmap -oX - --script smb-os-discovery.nse $Target *>&1";
    $OS = [Regex]::Match(([Xml]$Nmap).nmaprun.host.hostscript.script.output,'OS\:\s(.*?)\n').Value.Replace("OS: ","").Trim();
    
    # Check and see if we got a result
    if ($OS) {
        $Result.ScanInfo.OS = $OS;
    } else {
        $Result.ScanInfo.OS = "Unknown (Nmap)";
    }
     
} catch {
    $Result.ScanInfo.OS = "Unknown (Nmap)";
}

# Test for WinRM and WMI connectivity if OS is Windows or Unknown
if ($("Windows","Unknown"|%{if($Result.ScanInfo.OS.Contains($_)){$True}})) {
    
    # Set a bool we can reverse later for whether to perform the check
    $WinRm = $False;

    # Work out whether we need to use TLS or not for WinRM and whether it's available
    if ((Test-NetConnection -ComputerName $Target -Port 5986).TcpTestSucceeded) {
        $Result.RemoteConnection.WinRm.UseTls = $True;
        $WinRm = $True;
    } elseif ((Test-NetConnection -ComputerName $Target -Port 5985).TcpTestSucceeded) {
        $Result.RemoteConnection.WinRm.UseTls = $False;
        $WinRm = $True;
    } else {
        $WinRm = $False;
        $Result.RemoteConnection.WinRm.Success = $False;
        $Result.RemoteConnection.WinRm.Error = "Ports 5985|5986 not open on target host";
    }
    
    # Try a WinRM connection based on what we learned earlier
    if ($WinRm) {

        # Build our WinRM params
        $WinRmParams = @{
            ComputerName = $Target;
            Authentication = "Negotiate";
            Credential = $WindowsCredential;
            UseSsl = $Result.RemoteConnection.WinRm.UseTls;
            ScriptBlock = {Get-WmiObject -Class "Win32_OperatingSystem" | Select -ExpandProperty Caption};
        }

        # Try to get the result and replace the guessed OS
        try {
            $WinRmResult = Invoke-Command @WinRmParams;
            $Result.ScanInfo.OS = $WinRmResult;
            $Result.RemoteConnection.WinRm.Success = $True;
        } catch {
            $Result.RemoteConnection.WinRm.Success = $False;

            # Try to parse the exception as XML
            if ($(try{([Xml]$_.Exception.Message).DocumentElement.Message}catch{})) {
                $Result.RemoteConnection.WinRm.Error = ([Xml]$_.Exception.Message).DocumentElement.Message;
            } else {
                $Result.RemoteConnection.WinRm.Error = $_.Exception.Message;
            }
        }
    }
    
    # Try using WMI to access the target machine
    try {
        # Splat up the WMI params
        $WmiParams = @{
            ComputerName = $Target;
            Credential = $WindowsCredential;
            Class = "Win32_OperatingSystem";
        }
        
        # Try to get the result and replace the guessed OS
        $WmiResult = Get-WmiObject @WmiParams | Select -ExpandProperty Caption;
        $Result.ScanInfo.OS = $WmiResult;
        $Result.RemoteConnection.Wmi.Success = $True;
    }
    catch {
        $Result.RemoteConnection.Wmi.Success = $False;
        $Result.RemoteConnection.Wmi.Error = $_.Exception.Message;
    }
} else {
    # Set our WMI/WinRM to skipped
    $Result.RemoteConnection.WinRm.Success = $False;
    $Result.RemoteConnection.WinRm.Error = "Skipped";
    
    $Result.RemoteConnection.Wmi.Success = $False;
    $Result.RemoteConnection.Wmi.Error = "Skipped";
}

# Test for SSH connectivity if OS is Linux/Unix based (or unknown)
if ($("Linux","Unix","Solaris","HP-UX","BSD","Unknown"|%{if($Result.ScanInfo.OS.Contains($_)){$True}})) {
    try {
        # Generate a unique echo we can use
        $Echo = [Guid]::NewGuid().Guid;
       
        # Try credential based authentication
        if ($LinuxUsername -and $LinuxPassword) {
            
            # Cmd
            $Cmd = "plink -ssh $Target -P 22 -l $LinuxUsername -pw $LinuxPassword -batch echo $Echo";

            # Invoke
            $PlinkResult = Invoke-Expression $Cmd;

            # Check
            if ($PlinkResult -like "*$Echo*") {
                
                # Store the result
                $Result.RemoteConnection.Ssh.UseCredentials = $True;
                $Result.RemoteConnection.ssh.Success = $True;

                # Get a uname for this host using this connection method
                $UnameCmd = "plink -ssh $Target -P 22 -l $LinuxUsername -pw $LinuxPassword -batch uname -srv";
                $Result.ScanInfo.OS = Invoke-Expression $UnameCmd;

            } else {
                $Result.RemoteConnection.Ssh.UseCredentials = $False;
            }
        }

        # Try private key authentication without passphrase
        if ($LinuxUsername -and $PrivateKeyFilePath) {

            # Cmd
            $Cmd = "plink -ssh $Target -P 22 -l $LinuxUsername -i $LinuxPrivateKeyFile -batch echo $Echo";

            # Invoke
            $PlinkResult = Invoke-Expression $Cmd;

            # Check
            if ($PlinkResult -like "*$Echo*") {

                # Store the result
                $Result.RemoteConnection.Ssh.UsePrivateKey = $True;
                $Result.RemoteConnection.ssh.Success = $True;

                # Get a uname for this host using this connection method
                $UnameCmd = "plink -ssh $Target -P 22 -l $LinuxUsername -i $LinuxPrivateKeyFile -batch uname -srv";
                $Result.ScanInfo.OS = Invoke-Expression $UnameCmd;

            } else {
                $Result.RemoteConnection.Ssh.UsePrivateKey = $False;
            }
        }

        # Try private key authentication with passphrase
        if ($LinuxUsername -and $LinuxPrivateKeyFile -and $LinuxPrivateKeyPassphrase) {

            # Wrap the ssh connection in a Process so we can write to stdin
            $ProcessStartInfo = New-Object System.Diagnostics.ProcessStartInfo;
            $Process = New-Object System.Diagnostics.Process;

            # Set the startinfo object properties and set the process to use this startinfo
            $ProcessStartInfo.FileName = $($env:windir + "\System32\cmd.exe");
            $ProcessStartInfo.CreateNoWindow = $True;
            $ProcessStartInfo.UseShellExecute = $False;
            $ProcessStartInfo.RedirectStandardOutput = $True;
            $ProcessStartInfo.RedirectStandardInput = $True;
            $ProcessStartInfo.RedirectStandardError = $True;
            $Process.StartInfo = $ProcessStartInfo;

            # Start the process
            [Void]($Process.Start());

            # Cmd and execute
            $Cmd = "plink -ssh $Target -P 22 -l $LinuxUsername -i $LinuxPrivateKeyFile echo $Echo";
            $Process.StandardInput.Write($Cmd + [System.Environment]::NewLine);
            
            # Wait for 2 seconds and write the private key passphrase to stdin
            Start-Sleep -Seconds 2;
            $Process.StandardInput.Write($LinuxPrivateKeyPassphrase + [System.Environment]::NewLine);

            # Close stdin now we're done with it
            $Process.StandardInput.Close();

            # Block the exit until completion
            $Process.WaitForExit();

            # Grab stderr, stdout and exit code in case we need to throw
            $Stderr = $Process.StandardError.ReadToEnd();
            $Stdout = $Process.StandardOutput.ReadToEnd();
            $Status = $Process.ExitCode;

            # Check
            if (($Stdout.Split("`r`n") | ?{$_ -and $_ -notlike "*\system32*"} | Select -Last 1) -like "*$Echo*") {

                # Store the result
                $Result.RemoteConnection.Ssh.UsePrivateKeyPassphrase = $True;
                $Result.RemoteConnection.ssh.Success = $True;

                # Spin up the process again
                [Void]($Process.Start());

                # Cmd and execute
                $Cmd = "plink -ssh $Target -P 22 -l $LinuxUsername -i $LinuxPrivateKeyFile uname -srv";
                $Process.StandardInput.Write($Cmd + [System.Environment]::NewLine);
            
                # Wait for 2 seconds and write the private key passphrase to stdin
                Start-Sleep -Seconds 2;
                $Process.StandardInput.Write($LinuxPrivateKeyPassphrase + [System.Environment]::NewLine);

                # Close stdin now we're done with it
                $Process.StandardInput.Close();

                # Block the exit until completion
                $Process.WaitForExit();

                # Grab stderr, stdout and exit code in case we need to throw
                $Stderr = $Process.StandardError.ReadToEnd();
                $Stdout = $Process.StandardOutput.ReadToEnd();
                $Status = $Process.ExitCode;

                # Get a uname for this host using this connection method
                $Result.ScanInfo.OS = ($Stdout.Split("`r`n") | ?{$_ -and $_ -notlike "*\system32*"} | Select -Last 1);

            } else {
                $Result.RemoteConnection.Ssh.UsePrivateKeyPassphrase = $False;
            }

        }
    } 
    catch {
        $Result.RemoteConnection.Ssh.Success = $False;
        $Result.RemoteConnection.Ssh.Error = $_.Exception.Message;
    }
} else {
    $Result.RemoteConnection.Ssh.Success = $False;
    $Result.RemoteConnection.Ssh.Error = "Skipped";
}

# Set our RemoteConnectivity health property based on what we know now
$r_winrm = $($Result.RemoteConnection.WinRm.Success -eq $True);
$r_wmi = $($Result.RemoteConnection.Wmi.Success -eq $True);
$r_ssh = $($Result.RemoteConnection.Ssh.Success -eq $True);

if ($r_winrm -or $r_wmi -or $r_ssh) {
    $Result.RemoteConnection.Healthy = $True;
} else {
    $Result.RemoteConnection.Healthy = $False;
}

# Set our scan time for this host
$EndTime = Get-Date;
$Result.ScanInfo.TimeTaken = $(New-TimeSpan $StartTime $EndTime);

# And return the result
return $Result;