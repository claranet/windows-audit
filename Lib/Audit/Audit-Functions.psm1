# Helper function to convert subnet mask to binary
Function Convert-Subnetmask {
    [CmdLetBinding(DefaultParameterSetName="CIDR")]
    Param( 
        [Parameter(ParameterSetName="CIDR",Position=0,Mandatory=$True)]
        [ValidateRange(0,32)]
        [Int32]$CIDR,

        [Parameter(ParameterSetName="Mask",Position=0,Mandatory=$True)]
        [ValidateScript({
            if ($_ -match "^(255|254|252|248|240|224|192|128).0.0.0$|^255.(254|252|248|240|224|192|128|0).0.0$|^255.255.(254|252|248|240|224|192|128|0).0$|^255.255.255.(255|254|252|248|240|224|192|128|0)$")
            {
                return $True;
            }
            else 
            {
                throw "Enter a valid subnetmask e.g. 255.255.255.0";
            }
        })]
        [String]$Mask
    )

    # Switch based on the operation we're doing
    Switch($PSCmdlet.ParameterSetName)
    {
        "CIDR" {                          
            # Make a string of bits (24 to 11111111111111111111111100000000)
            $CIDR_Bits = ("1" * $CIDR).PadRight(32,"0");
                    
            # Split into groups of 8 bits, convert to Ints, join up into a string
            $Octets = $CIDR_Bits -split "(.{8})" -ne "";
            $Mask = ($Octets | %{[Convert]::ToInt32($_,2)}) -join ".";
        }

        "Mask" {
            # Convert the numbers into 8 bit blocks, join them all together, count the 1
            $Octets = $Mask.ToString().Split(".") | %{[Convert]::ToString($_,2)};
            $CIDR_Bits = ($Octets -join "").TrimEnd("0");

            # Count the "1" (111111111111111111111111 --> /24)                    
            $CIDR = $CIDR_Bits.Length;   
        }               
    }

    # And return
    return $([PSCustomObject]@{
        Mask = $Mask
        CIDR = $CIDR
    });
}

# Helper function to convert an IPv4-Address to Int64 and vise versa
Function Convert-IPv4Address {
    [CmdletBinding(DefaultParameterSetName="IPv4Address")]
    Param(
        [Parameter(ParameterSetName="IPv4Address",Position=0,Mandatory=$True)]
        [IPaddress]$IPv4Address,

        [Parameter(ParameterSetName="Int64",Position=0,Mandatory=$True)]
        [Long]$Int64
    ) 

    # Switch based on the operation we're doing
    switch($PSCmdlet.ParameterSetName)
    {
        # Convert IPv4-Address as string into Int64
        "IPv4Address" {
            $Octets = $IPv4Address.ToString().Split(".");
            $Int64 = [Long]([Long]$Octets[0]*16777216 + [Long]$Octets[1]*65536 + [Long]$Octets[2]*256 + [Long]$Octets[3]);
        }
        
        # Convert IPv4-Address as Int64 into string 
        "Int64" {            
            $IPv4Address = @(
                ([System.Math]::Truncate($Int64/16777216)).ToString(),
                ([System.Math]::Truncate(($Int64%16777216)/65536)).ToString(),
                ([System.Math]::Truncate(($Int64%65536)/256)).ToString(),
                ([System.Math]::Truncate($Int64%256)).ToString()
            ) -Join ".";
        }      
    }

    # And return
    return $([PSCustomObject]@{   
        IPv4Address = $IPv4Address;
        Int64       = $Int64;
    });
}

# Helper function to create a new Subnet
Function Get-IPv4Subnet {
    [CmdletBinding(DefaultParameterSetName="CIDR")]
    Param(
        [Parameter(Position=0,Mandatory=$True)]
        [IPAddress]$IPv4Address,

        [Parameter(ParameterSetName="CIDR",Position=1,Mandatory=$True)]
        [ValidateRange(0,32)]
        [Int32]$CIDR,

        [Parameter(ParameterSetName="Mask",Position=1,Mandatory=$True)]
        [ValidateScript({
            if ($_ -match "^(255|254|252|248|240|224|192|128).0.0.0$|^255.(254|252|248|240|224|192|128|0).0.0$|^255.255.(254|252|248|240|224|192|128|0).0$|^255.255.255.(255|254|252|248|240|224|192|128|0)$")
            {
                return $True;
            }
            else 
            {
                throw "Enter a valid subnetmask e.g. 255.255.255.0"; 
            }
        })]
        [String]$Mask
    )

    # Convert Mask or CIDR - because we need both in the code below
    switch($PSCmdlet.ParameterSetName)
    {
        "CIDR" {                          
            $Mask = (Convert-Subnetmask -CIDR $CIDR).Mask;
        }
        "Mask" {
            $CIDR = (Convert-Subnetmask -Mask $Mask).CIDR;
        }                  
    }
            
    # Get CIDR Address by parsing it into an IP-Address
    $CIDRAddress = [System.Net.IPAddress]::Parse([System.Convert]::ToUInt64(("1"* $CIDR).PadRight(32,"0"),2));
        
    # Binary AND ... this is how subnets work.
    $NetworkID_bAND = $IPv4Address.Address -band $CIDRAddress.Address;

    # Return an array of bytes. Then join them.
    $NetworkID = [System.Net.IPAddress]::Parse([System.BitConverter]::GetBytes([UInt32]$NetworkID_bAND) -join ("."));
            
    # Get HostBits based on SubnetBits (CIDR) // Hostbits (32 - /24 = 8 -> 00000000000000000000000011111111);
    $HostBits = ("1" * (32 - $CIDR)).PadLeft(32,"0");
            
    # Convert Bits to Int64
    $AvailableIPs = [Convert]::ToInt64($HostBits,2);

    # Convert Network Address to Int64
    $NetworkID_Int64 = (Convert-IPv4Address -IPv4Address $NetworkID.ToString()).Int64;

    # Convert add available IPs and parse into IPAddress
    $Broadcast = [System.Net.IPAddress]::Parse((Convert-IPv4Address -Int64 ($NetworkID_Int64 + $AvailableIPs)).IPv4Address);
            
    # Change useroutput ==> (/27 = 0..31 IPs -> AvailableIPs 32)
    $AvailableIPs += 1;

    # Hosts = AvailableIPs - Network Address + Broadcast Address
    $Hosts = ($AvailableIPs - 2);
                
    # And return
    return $([PSCustomObject]@{
        NetworkID = $NetworkID;
        Broadcast = $Broadcast;
        IPs       = $AvailableIPs;
        Hosts     = $Hosts;
    });
}

# Returns a group of TimeZone display names that match a supplied UTC offset in minutes
Function Get-TimeZoneDisplayName {
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [Int]$UTCOffsetMinutes
    )

    # Let's convert the UTC offset to a formatted hours string for comparison
    $UTCOffsetHours = "{0:D2}:00:00" -F $($UTCOffsetMinutes / 60);

    # Get a list of zones that match the formatted UTC offset
    $Zones = [System.TimeZoneInfo]::GetSystemTimeZones() | ?{$_.BaseUtcOffset -eq $UTCOffsetHours};

    # Return a pipe seperated list of matching zones
    return $Zones.DisplayName -join " | ";
}

# Returns a CultureInfo name from a supplied WMI locale code
Function Get-LocaleFromWMICode {
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$WMILocaleCode # String to preserve leading zeroes
    )

    # Get our Hex number style and Invariant information
    $HexNumber  = [System.Globalization.NumberStyles]::HexNumber;
    $InvarInfo  = [System.Globalization.NumberFormatInfo]::InvariantInfo;

    # Declare our ref var and parse to int
    $LocaleCode = 0;
    [Void]([Int]::TryParse($WMILocaleCode, $HexNumber, $InvarInfo, [Ref]$LocaleCode));

    # Get and return our CultureInfo name
    return [CultureInfo]::GetCultureInfo($LocaleCode).Name;
}

# Returns a formatted date string diffing between a supplied datetime and now (or supplied datetime)
Function Get-DateTimeDifference {
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [DateTime]$CompareDateTime,
        [Parameter(Mandatory=$False,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [DateTime]$ReferenceDateTime = $(Get-Date)
    )

    # Get a timespan object we can base from
    $TimeSpan  = New-TimeSpan $CompareDateTime $ReferenceDateTime;

    # And return our formatted string
    return "{0} Days, {1} Hours, {2} Minutes" -f $TimeSpan.Days, $TimeSpan.Hours, $TimeSpan.Minutes;
}

# Returns a bool indicating whether the supplied string is an IPv4 address
Function Is-Ipv4Address {
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False,ValueFromPipeline=$True)]
        [String]$Address
    )

    # Pattern, will match any 32 bit 4 octet number but we know our inputs are good
    $Pattern = "\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b";

    # Return based on match
    Switch -Regex ($Address) {
        $Pattern {return $True}
        default  {return $False}
    }
}

# Returns a bool indicating whether the supplied string is an IPv6 address
Function Is-Ipv6Address {
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False,ValueFromPipeline=$True)]
        [String]$Address
    )

    # Pattern chopped up combined with a -join for legibility
    $Pattern = @(
        "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|",
        "([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}",
        ":){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:)",
        "{1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1",
        ",4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA",
        "-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9",
        "a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[",
        "0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:(",
        "(:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F",
        "]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4})",
        "{0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1",
        "}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0",
        ",1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(",
        "2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]",
        "|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
    ) -Join "";

    # Return based on match
    Switch -Regex ($Address) {
        $Pattern {return $True}
        default  {return $False}
    } 
}

# Converts a Win32_LogicalDisk MediaType enum to a description string
Function ConvertTo-DiskMediaTypeString {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateRange(0, 22)]
        [Int]$MediaTypeEnum
    )

    Switch($MediaTypeEnum) {
        0  {"Unknown media type"}
        1  {"5¼ Inch Floppy Disk - 1.2 MB - 512 bytes/sector"}
        2  {"3½ Inch Floppy Disk - 1.44 MB - 512 bytes/sector"}
        3  {"3½ Inch Floppy Disk - 2.88 MB - 512 bytes/sector"}
        4  {"3½ Inch Floppy Disk - 20.8 MB - 512 bytes/sector"}
        5  {"3½ Inch Floppy Disk - 720 KB - 512 bytes/sector"}
        6  {"5¼ Inch Floppy Disk - 360 KB - 512 bytes/sector"}
        7  {"5¼ Inch Floppy Disk - 320 KB - 512 bytes/sector"}
        8  {"5¼ Inch Floppy Disk - 320 KB - 1024 bytes/sector"}
        9  {"5¼ Inch Floppy Disk - 180 KB - 512 bytes/sector"}
        10 {"5¼ Inch Floppy Disk - 160 KB - 512 bytes/sector"}
        11 {"Removable media other than floppy"}
        12 {"Fixed hard disk media"}
        13 {"3½ Inch Floppy Disk - 120 MB - 512 bytes/sector"}
        14 {"3½ Inch Floppy Disk - 640 KB - 512 bytes/sector"}
        15 {"5¼ -Inch Floppy Disk - 640 KB - 512 bytes/sector"}
        16 {"5¼ -Inch Floppy Disk - 720 KB - 512 bytes/sector"}
        17 {"3½ Inch Floppy Disk - 1.2 MB - 512 bytes/sector"}
        18 {"3½ Inch Floppy Disk - 1.23 MB - 1024 bytes/sector"}
        19 {"5¼ Inch Floppy Disk - 1.23 MB - 1024 bytes/sector"}
        20 {"3½ Inch Floppy Disk - 128 MB - 512 bytes/sector"}
        21 {"3½ Inch Floppy Disk - 230 MB - 512 bytes/sector"}
        22 {"8 Inch Floppy Disk - 256 KB - 128 bytes/sector"}
    }
}

# Converts a Win32_LogicalDisk DriveType enum to a description string
Function ConvertTo-DiskDriveTypeString {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateRange(0, 6)]
        [Int]$DriveTypeEnum
    )

    Switch($DriveTypeEnum) {
        0 {"Unknown media type"}
        1 {"No Root Directory"}
        2 {"Removable Disk"}
        3 {"Local Disk"}
        4 {"Network Drive"}
        5 {"Compact Disc"}
        6 {"RAM Disk"}
    }
}

# Returns a bool indicating if HyperThreading is enabled based on supplied core counts
Function Is-HyperThreadingEnabled {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [Int]$PhysicalCores,
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [Int]$LogicalCores
    )

    if ($LogicalCores -eq (2 * $PhysicalCores)) {
        return $True;
    }
    else {
        return $False;
    }
}

# Invokes a PowerShell-over-PSExec command
Function Invoke-PSExecCommand {
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$ComputerName,
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$ScriptFile,
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]$PSCredential
    )

    try {

        # Get the username and password from the PSCredential
        $Username = $PSCredential.UserName;
        $Password = $PSCredential.GetNetworkCredential().Password;

        # Check for inescapable characters
        """","'","&","^" | %{
            if ($Password.Contains($_)) {
                throw 'Your password contains the "'+$_+'" character which is incompatible with the escaping of PSExec, please change your password or use a different credential';
            }
        }

        # Get the contents of the script
        $Content = Get-Content $ScriptFile;

        # Trim out the fat
        $Content = $Content | ?{$_ -notmatch '#(.*)' -and ![String]::IsNullOrEmpty($_)} | Out-String;

        # Encode it to a base 64 string
        $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Content);
        $Encoded = [Convert]::ToBase64String($Bytes);

        # Generate our temp filename
        $FileName = [Guid]::NewGuid().Guid + ".txt";

        # Define the chunk pointer and size we want to transmit
        $ChunkPointer = 0;
        $ChunkSize = 210;

        # Loop over the encoded string and chunk it
        While ($ChunkPointer -le ($Encoded.Length-$ChunkSize)) {

            # Get the chunk we want to transmit
            $Chunk = $Encoded.Substring($ChunkPointer,$ChunkSize);

            # Build the command
            $Local = "echo $Chunk >> $Filename";
            $Cmd = 'cmd /c psexec -accepteula -nobanner \\{0} -u {1} -p """{2}""" cmd /c "{3}" --% 2>&1' -f $ComputerName,$Username,$Password,$Local;

            # Transmit the chunk
            $Row = Invoke-Expression $Cmd | ?{$_ -like "*error*"};
            if ($Row -notlike "*error code 0*") {
                throw $Row;
            }

            # Increment the chunk pointer
            $ChunkPointer += $ChunkSize;
    
            # Progress meter
            Write-Progress `
                -Activity "Transferring '$ScriptFile' over PSExec" `
                -Status "Processing chunk $($ChunkPointer/$ChunkSize) of $([Math]::Ceiling($Encoded.Length/$ChunkSize))" `
                -PercentComplete $(((($ChunkPointer/$ChunkSize)/($Encoded.Length/$ChunkSize)))*100);

        }

        # Grab the last portion and transmit it
        Write-Progress -Activity "Transferring '$ScriptFile' over PSExec" -Status "Processing final chunk";
        $Chunk = $Encoded.Substring($ChunkPointer);
        $Local = "echo $Chunk >> $Filename";
        $Cmd = 'cmd /c psexec -accepteula -nobanner \\{0} -u {1} -p """{2}""" cmd /c "{3}" --% 2>&1' -f $ComputerName,$Username,$Password,$Local;
        $Row = Invoke-Expression $Cmd | ?{$_ -like "*error*"};
        if ($Row -notlike "*error code 0*") {
            throw $Row;
        }
        Write-Progress -Activity "Transferring '$ScriptFile' over PSExec" -Completed;

        # Now we want to re-assemble the file
        Write-ShellMessage -Message "Assembling script file" -Type DEBUG;
        $Assemble = '$C=Get-Content {0}|Out-String;$B=[Convert]::FromBase64String($C);$S=[System.Text.Encoding]::Unicode.GetString($B);Set-Content Audit-ScriptBlock.ps1 -value $S' -f $FileName;
        $PSExec = "psexec -accepteula -nobanner \\$ComputerName -u $Username -p """"""$Password"""""" PowerShell -ExecutionPolicy Unrestricted -Command '$Assemble'";
        $Row = Invoke-Expression $("cmd /c $PSExec --% 2>&1") | ?{$_ -like "*error*"};
        if ($Row -notlike "*error code 0*") {
            throw $Row;
        }

        # Invoke the script
        Write-ShellMessage -Message "Executing script file" -Type DEBUG;
        $Cmd = 'cmd /c psexec -accepteula -nobanner \\{0} -u {1} -p """{2}""" PowerShell -ExecutionPolicy Unrestricted -File Audit-ScriptBlock.ps1 -X --% 2>&1' -f $ComputerName,$Username,$Password;
        $Result = Invoke-Expression $Cmd;
        if ($Row -notlike "*error code 0*") {
            throw $Row;
        }

        # Now delete the trash
        Write-ShellMessage -Message "Cleaning up" -Type DEBUG;
        $Cmd = 'cmd /c psexec -accepteula -nobanner \\{0} -u {1} -p """{2}""" cmd /c "del /f Audit-ScriptBlock.ps1,{3}" --% 2>&1' -f $ComputerName,$Username,$Password,$FileName;
        $Row = Invoke-Expression $Cmd | ?{$_ -like "*error*"};
        if ($Row -notlike "*error code 0*") {
            throw $Row;
        }

        # Clean the result
        Write-ShellMessage -Message "Readying results" -Type DEBUG;
        $Result = $($Result | ?{`
            $_ -and `
            $_ -notlike "Connecting to *" -and `
            $_ -notlike "Starting PSEXESVC service*" -and `
            $_ -notlike "Connecting with PsExec *" -and `
            $_ -notlike "Starting PowerShell on *" -and `
            $_ -notlike "PowerShell exited on *"`
        }) -join "`r`n";

        # Check here see if we got the XML
        if ($Result.Contains("<Objs")) {  
            $Output = $Result.Substring(0,$Result.IndexOf("<Objs"));
            $XML = $Result.Replace($Output,"");
        } 
        else {
            $Output = $Result;
        }

        # Write the captured output
        $Output.Split("`r`n") | ?{$_} | %{
            # Work out what colour it should be
            Switch -Regex ($_) {
                "DEBUG\]\:"   {$Col = "Magenta"};
                "INFO\]\:"    {$Col = "Cyan"};
                "WARNING\]\:" {$Col = "Yellow"};
                "SUCCESS\]\:" {$Col = "Green"};
                "ERROR\]\:"   {$Col = "Red"};
                default       {$Col = "White"};
            }
            # Write it
            Write-Host $_ -ForegroundColor $Col;
        }

        # Check if we got the XML
        if ($XML) {
            # Deserialise the info
            $HostInformation = [System.Management.Automation.PSSerializer]::Deserialize($XML);
            
            # And return the host information
            return $HostInformation;
        }
        else {
            throw "Unable to find return XML in PSExec output.";
        }

    }
    catch {
        Write-ShellMessage -Message "Error running script '$ScriptFile' on server '$ComputerName': $($_ -join " ")" -Type ERROR;
        Exit(1);
    }
}

# Writes pretty log messages
Function Write-ShellMessage {
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$Message,
        [Parameter(Mandatory=$True)]
        [ValidateSet("DEBUG","INFO","WARNING","SUCCESS","ERROR")]
        [String]$Type,
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    # Get a datestamp sorted
    $DateStamp = Get-Date -Format "dd/MM/yy HH:mm:ss";

    # Build our message output
    $Output = [String]::Format("[{0}] [{1}]: {2}",$DateStamp,$Type,$Message);
    
    # If we have an ErrorRecord attach the message at the end
    if ($ErrorRecord) {
        $Output += ": $($ErrorRecord.Exception.Message)";
    }

    # Swiffy to determine colour
    Switch ($Type) {
        "DEBUG"   {$C = "Magenta"};
        "INFO"    {$C = "Cyan"};
        "WARNING" {$C = "Yellow"};
        "SUCCESS" {$C = "Green"};
        "ERROR"   {$C = "Red"};
    }

    # Check debug preference and write out
    if ($Type -eq "DEBUG") {
        if ($DebugPreference -eq "Continue") {
            Write-Host $Output -ForegroundColor $C;
        }
    }
    else {
        Write-Host $Output -ForegroundColor $C;
    }
}

# Writes error log messages to file
Function Write-ErrorLog {
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$Hostname,
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$EventName,
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]$Exception,
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]$Sanitise
    )

    # Get a datestamp sorted
    $DateStamp = Get-Date -Format "dd/MM/yy HH:mm:ss";

    # Build our message output
    $Output = [String]::Format("[{0}] [{1}] [{2}]: {3}",$DateStamp,$HostName,$EventName,$Exception);

    # Quick cleanup
    $Sanitise | %{
        $Output = $Output.Replace($_,"******");
    }
    
    # Check if our errors file exists and create if needed
    $ErrorsFile = ".\errors.log";
    if (!(Test-Path $ErrorsFile)) {
        [Void](New-Item $ErrorsFile -ItemType File);
    }

    # Add the content to the file
    Add-Content -Path $ErrorsFile -Value $Output;
}

# Tests a remote connection and returns the available connection method
Function Test-RemoteConnection {
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$ComputerName,
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]$PSCredential
    )

    # Try WinRM connection as this is preferred
    if (Test-WSMan -ComputerName $ComputerName -Credential $PSCredential -Authentication Default -ErrorAction SilentlyContinue) {
        return "WinRM";
    }

    # Get the standard creds for PSExec in scope
    $Username = $PSCredential.UserName;
    $Password = $PSCredential.GetNetworkCredential().Password;

    # Check for inescapable characters
    """","'","&","^" | %{
        if ($Password.Contains($_)) {
            throw 'Your password contains the "'+$_+'" character which is incompatible with the escaping of PSExec, please change your password or use a different credential';
        }
    }

    # PSExec, fallback connection test
    $Cmd = 'cmd /c psexec \\{0} -u {1} -p """{2}""" /accepteula cmd /c echo connectionsuccessfulmsg --% 2>&1' -f $ComputerName,$Username,$Password;
    $PSExecResult = Invoke-Expression $Cmd;

    if (($PSExecResult -Join " ").Contains("connectionsuccessfulmsg")) {
        # Let's check to see if powershell works
        $Cmd = 'cmd /c psexec \\{0} -u {1} -p """{2}""" /accepteula powershell -ExecutionPolicy unrestricted -Command "return ""pshellsuccess""" --% 2>&1' -f $ComputerName,$Username,$Password;
        $PSResult = Invoke-Expression $Cmd;

        if (($PSResult -Join " ").Contains("pshellsuccess")) {
            return "PSExec";
        }
        else {
            throw "The machine '$ComputerName' has an issue starting powershell, please correct this before trying to audit this machine. Stack: $($PSResult -join " ")"
            return;
        }
    }

    # No remote connectivity
    $ErrorMessage = "The machine '$ComputerName' is not responding on any communication method. Please enable WinRM or PSExec on the target machine and try again";
    throw [System.PlatformNotSupportedException] $ErrorMessage;
}

# Filters applications to ignore junk
Filter ApplicationFilter {
    # Get the pipeline object
    $Application = $_;

    # Quick null check on the Application object
    if ($Application) {

        # Get the application name
        $ApplicationName = $Application.DisplayName;

        # Null match on name
        $IsNotNull = ![String]::IsNullOrEmpty($ApplicationName);

        # Direct matches
        $NoDirectMatch = @(
            " Overlook Fing",
            ".NET Sql Authorization Manager",
            "Active Directory Migration Tool",
            "ADePT Design Suite 1.4",
            "Administrative Templates (ADMX) for Windows 10 and Windows Server 2016",
            "Angry IP Scanner",
            "Amtech LiveUpdate",
            "AOMEI Partition Assistant Lite Edition 6.0",
            "Apple Application Support",
            "Apple Mobile Device Support",
            "Application Configurator",
            "ASDK Documents and Samples",
            "AspEmail",
            "AspJpeg",
            "AspPDF",
            "AspUpload",
            "Assessment and Deployment Kit",
            "Asset Management Upgrade",
            "AutomationLanguages",
            "AzureTools.Notifications",
            "ConsoleUpgradeLanguages",
            "Dell System E-Support Tool (3.2)",
            "Dell Troubleshoot Tool",
            "DellMCDocumentation",
            "DellMCDocumentationLanguages",
            "Diagnostics",
            "DiagnosticsHub_CollectionService",
            "DiagnosticsLanguages",
            "DirectoryConnectorUpgrade",
            "DirectoryConnectorUpgradeLanguages",
            "DirectoryServicesLanguages",
            "DiscoveryTasks",
            "DiscoveryTasksLP",
            "Doc-To-Help",
            "Ghostbuster",
            "Idera PowerShellPlus Professional Edition (x64)",
            "InstallShield 2015 Limited Edition",
            "Integral Client SDK v7.0.70.4",
            "Intel(R) Control Center",
            "Intel(R) Management Engine Components",
            "Intel(R) Network Connections 15.5.74.0",
            "Intel(R) Network Connections 18.5.54.0",
            "Intel(R) SDK for OpenCL - CPU Only Runtime Package",
            "Intel® Trusted Connect Service Client",
            "Intellisense Lang Pack Mobile Extension SDK 10.0.15063.0",
            "iTunes",
            "Microsoft Document Explorer 2008",
            "Microsoft Robocopy GUI",
            "Microsoft VC++ redistributables repacked",
            "Microsoft® Office Web Apps",
            "Outils de vérification linguistique 2013 de Microsoft Office - Français",
            "pcAnywhere Upgrade",
            "Pidgin",
            "Recover My Files",
            "Remote Desktop Manager",
            "Skype for Business Online, Windows PowerShell Module",
            "smtp4dev 2.1 alpha 1",
            "Unlocker",
            "VC Runtimes MSI",
            "Vhd Resizer",
            "Visualization Content",
            "WebControlsLanguagesLanguages",
            "winpcap-overlook 4.02",
            "XML Notepad 2007",
            " Tools for .Net 3.5",
            ".NET Core SDK 1.0.3 (x64)",
            "2007 Microsoft Office Suite Service Pack 2 (SP2)",
            "Adobe Acrobat Reader DC",
            "AvImporter",
            "Bonjour",
            "Broadcom Drivers and Management Applications",
            "Broadcom Management Programs",
            "Broadcom NetXtreme II Driver Installer",
            "Broadcom NetXtreme-I Netlink Driver and Management Installer",
            "ClickOnce Bootstrapper Package for Microsoft .NET Framework",
            "Compatibility Pack for the 2007 Office system",
            "DAEMON Tools Lite",
            "Debugging Tools for Windows (x64)",
            "Debugging Tools for Windows (x86)",
            "DHTML Editing Component",
            "Duplicate File Finder",
            "Fiddler",
            "File System Analyzer 1.8.1.02279",
            "FileSeek 4.4",
            "FolderSizes 8",
            "Google Chrome",
            "Google Update Helper",
            "Intel(R) Chipset Device Software",
            "Intel(R) Network Connections Drivers",
            "Intel(R) Processor Graphics",
            "Intel(R) USB 3.0 eXtensible Host Controller Driver",
            "IntelliTraceProfilerProxy",
            "Java Auto Updater",
            "Local Administrator Password Solution",
            "LockHunter 3.1, 32/64 bit",
            "MagicDisc 2.7.106",
            "Matrox Graphics Software (remove only)",
            "McAfee Product Improvement Program",
            "Microsoft .NET Native SDK",
            "Microsoft Application Error Reporting",
            "Microsoft Azure Mobile Services SDK V2.0",
            "Microsoft Azure Mobile Services Tools for Visual Studio - v1.4",
            "Microsoft Azure Shared Components for Visual Studio 2015 - v1.8",
            "Microsoft CCR and DSS Runtime 2008 R3",
            "Microsoft Device Emulator version 1.0 - ENU",
            "Microsoft Document Explorer 2005",
            "Microsoft Excel Mobile Viewer Components",
            "Microsoft Expression Blend SDK for .NET 4",
            "Microsoft InfoPath Form Services English Language Pack",
            "Microsoft National Language Support Downlevel APIs",
            "Microsoft NetStandard SDK",
            "Microsoft Office 2003 Web Components",
            "Microsoft Office 2007 Service Pack 3 (SP3)",
            "Microsoft Office 2010 Language Pack Service Pack 1 (SP1)",
            "Microsoft Office 2010 Primary Interop Assemblies",
            "Microsoft Office 2010 Service Pack 1 (SP1)",
            "Microsoft Office 365 OnRamp ActiveX Control",
            "Microsoft Office Access 2003 Runtime",
            "Microsoft Office Access MUI (English) 2010v",
            "Microsoft Office Access Setup Metadata MUI (English) 2010",
            "Microsoft Office Excel MUI (English) 2007",
            "Microsoft Office File Validation Add-In",
            "Microsoft Office Groove MUI (English) 2010",
            "Microsoft Office Office 32-bit Components 2010",
            "Microsoft Office OneNote MUI (English) 2010",
            "Microsoft Office Outlook MUI (English) 2007",
            "Microsoft Office Outlook MUI (English) 2010",
            "Microsoft Office PowerPoint MUI (English) 2007",
            "Microsoft Office PowerPoint MUI (English) 2010",
            "Microsoft Office Professional Plus 2010",
            "Microsoft Office Project MUI (English) 2010",
            "Microsoft Office Project Standard 2010",
            "Microsoft Office Publisher MUI (English) 2010",
            "Microsoft Online Services Sign-in Assistant",
            "Microsoft Policy Platform",
            "Microsoft Primary Interoperability Assemblies 2005",
            "Microsoft Project 2010 Service Pack 1 (SP1)",
            "Microsoft Project Standard 2010",
            "Microsoft RichCopy 4.0",
            "Microsoft Shared Components",
            "Microsoft Shared Coms English Language Pack",
            "Microsoft SharePoint Portal English Language Pack",
            "Microsoft Silverlight",
            "Microsoft SQL Server 2005 Upgrade Advisor (English)",
            "Microsoft SQL Server 2008 R2 Books Online",
            "Microsoft Windows Communication Foundation Diagnostic Pack for x86",
            "Microsoft Windows Performance Toolkit",
            "Microsoft.VisualStudio.Office365",
            "Microsoft_VisioProfessional_2010_x86_EN_r01",
            "MiniTool Power Data Recovery Free Edition 7.0",
            "Mozilla Maintenance Service",
            "MSBuild/NuGet Integration 14.0 (x86)",
            "Multi-Device Hybrid Apps using C# - Templates - ENU",
            "New Crystal Patch",
            "Open XML SDK 2.5 for Microsoft Office",
            "OWASP Zed Attack Proxy 2.6.0",
            "PAL",
            "PowerISO",
            "PreEmptive Analytics Visual Studio Components",
            "Prerequisites for SSDT ",
            "Process Navigator",
            "ProjectStandard_2010_x86_EN_R01",
            "Ranorex 5.4",
            "RDC",
            "Recuva",
            "Reliability Update for Microsoft .NET Framework 4.5.2 (KB3179930)",
            "Remote Desktop Connection Manager",
            "Remote Process Explorer version 3.1.0.151",
            "RoboMirror 1.3",
            "Roslyn Language Services - x86",
            "RSS FeedReader Web Part",
            "RVTools",
            "SafeCom Reports",
            "Shared Add-in Extensibility Update for Microsoft .NET Framework 2.0 (KB908002)",
            "Shared Add-in Support Update for Microsoft .NET Framework 2.0 (KB908002)",
            "SolarWinds Active Diagnostics 1.6.0.26",
            "SQL 2008 R2 Reporting Services SharePoint 2010 Add-in",
            "Sql Server Customer Experience Improvement Program",
            "SQLXML4",
            "SSMS Post Install Tasks",
            "SystemTools DumpSec",
            "Telerik UI for WinForms Q1 2015 SP1",
            "Test Tools for Microsoft Visual Studio 2015",
            "TextCrawler Free 3.0.3",
            "TG SD Calculator",
            "TightVNC 1.3.10",
            "TypeScript Power Tool",
            "TypeScript Tools for Microsoft Visual Studio 2015",
            "Universal General MIDI DLS Extension SDK",
            "Unlocker 1.9.2",
            "Update for  (KB2504637)",
            "Update for  (KB2504637)",
            "Update for 2007 Microsoft Office System (KB967642)",
            "Update for WSSLanguagePack (KB2553018)",
            "VC_CRT_x64",
            "VC90_CRT_x86",
            "vcpp_crt.redist.clickonce",
            "VDS 1.1 Update for R2",
            "Video Device Pack 6.2",
            "VirtualCloneDrive",
            "Visio Services Data Provider for System Center 2012 - Operations Manager",
            "Visual Studio Extensions for Windows Library for JavaScript",
            "Visual Studio Graphics Analyzer",
            "VS JIT Debugger",
            "VS Immersive Activate Helper",
            "VS Script Debugging Common",
            "VS Update core components",
            "VS WCF Debugging",
            "WCF RIA Services V1.0 SP2",
            "WinCDEmu",
            "Windows IP Over USB",
            "Windows Management Framework Core",
            "Windows NT Messaging",
            "Windows Runtime Intellisense Content - en-us",
            "Windows Search 4.0",
            "Windows Support Tools",
            "windows_toolscorepkg",
            "XML Paper Specification Shared Components Pack 1.0",
            "XMLImport",
            "Yahoo Search Set",
            "Ycopy 1.0d"
        ) -notcontains $ApplicationName

        # Like matches
        $NoLikeMatch = $True;
        @(
            "Active Directory Authentication Library for SQL Server",
            "Adobe Acrobat",
            "Adobe PDF",
            "Agile.NET",
            "Application Verifier",
            "Build Tools",
            "GoToMeeting",
            "Combined Community Codec Pack",
            "CutePDF",
            "Entity Framework *tools",
            "Foxit Reader",
            "GDR * for SQL Server",
            "Git version",
            "Google Chrome",
            "GoToMeeting",
            "GTK+ Runtime",
            "Hotfix for Windows Server",
            "icecap_collection_",
            "Java ",
            "Language Pack",
            "Microsoft ASP.NET ",
            "Microsoft Baseline Security",
            "Microsoft Device Emulator ",
            "Microsoft Forefront Threat Management Gateway Update",
            "Microsoft Office*MUI",
            "Microsoft OMUI",
            "Microsoft Outlook ",
            "Lang Pack",
            "Microsoft_InternetExplorer",
            "Secure Copy",
            "SlimDX Runtime",
            "SoapUI",
            "Windows Assessment and Deployment Kit",
            "WinPE",
            "7-Zip",
            "Adobe Flash Player",
            "Adobe Reader",
            "Adobe Refresh Manager",
            "Adobe Shockwave Player",
            "ATI Display Driver",
            "Citrix Hotfix",
            "DameWare",
            "Definition Update for Microsoft Office",
            "DelinvFile",
            "Easy RoboCopy  1.0.14",
            "GDR 1617 for SQL Server 2008 R2 (KB2494088) (64-bit)",
            "GDR 5057 for SQL Server Database Services 2005 ENU (KB2494120)",
            "GDR 5057 for SQL Server Tools and Workstation Components 2005 ENU (KB2494120)",
            "Hotfix 5646 for SQL Server 2012 (KB3137745) (64-bit)",
            "Hotfix for Microsoft .NET Framework 3.5 SP1 (KB953595)",
            "Hotfix for Microsoft Visual Studio 2007 Tools for Applications - ENU (KB946040)",
            "Hotfix for Windows Server 2003 (KB2158563)",
            "Hotfix for Windows SharePoint Services 3.0 (KB2817329) 64-Bit Edition",
            "Hotfix for Windows XP (KB954550-v5)",
            "Intellisense Lang Pack Mobile Extension SDK 10.0.14393.0",
            "Java(TM) 6 Update",
            "Java(TM) 7 Update",
            "LiveUpdate 3.3 (Symantec Corporation)",
            "Microsoft .NET Compact",
            "Microsoft .NET Core",
            "Microsoft .NET Framework",
            "Microsoft Agents for Visual Studio 2015",
            "Microsoft Blend for Visual Studio 2015",
            "Microsoft Build Tools",
            "Microsoft Chart Controls for Microsoft .NET Framework",
            "Microsoft Document Lifecycle Components",
            "Microsoft Exchange Client Language Pack - ",
            "Microsoft Exchange Server Language Pack - ",
            "Microsoft Filter Pack",
            "Microsoft Help Viewer",
            "Microsoft Identity Extensions",
            "Microsoft Kernel-Mode Driver Framework Feature Pack",
            "Microsoft NuGet ",
            "Microsoft Office Proof",
            "Microsoft Office Server Proof",
            "Microsoft Office Shared",
            "Microsoft Office Standard",
            "Microsoft Office Visio",
            "Microsoft Office Word",
            "Microsoft Portable Library",
            "Microsoft Report Viewer",
            "Microsoft ReportViewer",
            "Microsoft Server Speech ",
            "Microsoft Slide Library",
            "Microsoft SQL Server 2005 Books Online (English)",
            "Microsoft Visio ",
            "Microsoft Visual ",
            "Microsoft Web Analytics ",
            "Microsoft Web Platform Installer",
            "Microsoft Windows SDK ",
            "Microsoft Workflow ",
            "Microsoft WSE ",
            "Mozilla Firefox ",
            "MSXML ",
            "Notepad++",
            "Nmap ",
            "Npcap ",
            "PDF-XChange ",
            "PerformancePoint Services",
            "PuTTY ",
            "Remote Tools for Visual Studio",
            "ScreenConnect Client ",
            "Security Update for Microsoft",
            "Security Update for Windows",
            "Service Pack 1 for ",
            "Service Pack 2 for ",
            "Service Pack 3 for ",
            "Service Pack 4 for ",
            "sptools_Microsoft.VisualStudio",
            "The 2007 Microsoft Office Servers Service Pack 2 (SP2)",
            "TreeSize ",
            "Universal CRT ",
            "Update 4.0.3 for Microsoft .NET",
            "Update for Microsoft ",
            "Update for Windows ",
            "Update Rollup ",
            "User Productivity Kit ",
            "Visual Basic for Applications",
            "Visual C++ ",
            "Visual Studio 20",
            "vs_",
            "WCF Data Services",
            "Windows App Certification",
            "Windows Desktop Extension SDK",
            "Windows Espc ",
            "Windows Imaging",
            "Windows Internet Explorer",
            "Windows IoT Extension SDK",
            "Windows Mobile Connectivity Tools",
            "Windows Mobile Extension SDK",
            "Windows Phone SDK",
            "Windows Presentation Foundation",
            "Windows Resource Kit Tools",
            "Windows SDK ",
            "Windows Server 2003 Service Pack ",
            "Windows Simulator",
            "Windows Software Development Kit",
            "Windows Team Extension SDK",
            "WinPcap ",
            "WinRAR ",
            "WinRT Intellisense ",
            "WinSCP ",
            "Wireshark ",
            "Workflow Manager "
        ) | %{
            if ($ApplicationName -like "*$($_)*") {
                $NoLikeMatch = $False;
            }
        }

        # Check and return
        if ($IsNotNull -and $NoDirectMatch -and $NoLikeMatch) {
            $Application;
        }
    }
}

# Writes the final status message to both disk and screen
Function Write-FinalStatus {
[Cmdletbinding()]
Param(
    [Parameter(Mandatory=$True)]
    [System.Collections.ArrayList]$NodeCollection,
    [Parameter(Mandatory=$True)]
    [System.TimeSpan]$TS,
    [Parameter(Mandatory=$True)]
    [Int]$ProbeJobCount
)

# Get the network block of text made up
$NetworkBlock = @"
  Total possible nodes         : $ProbeJobCount
  Healthy nodes discovered     : $($NodeCollection.Where({$_.Status.Contains("Network Check Passed") -and ($_.IPAddress -or $_.Hostname)}).Count)
  Unreachable nodes discovered : $($NodeCollection.Where({$_.Status.Contains("Network Check Failed") -and ($_.IPAddress -or $_.Hostname)}).Count)
  ----
  Total nodes discovered       : $($NodeCollection.Where({$_.IPAddress -or $_.Hostname}).Count)
"@;

# Audit block of text
$AuditBlock = @"
  Nodes audited successfully   : $($NodeCollection.Where({$_.Completed -eq $True}).Count)
  Nodes audited with errors    : $($NodeCollection.Where({$_.Audited -eq $True -and ![String]::IsNullOrEmpty($_.AuditErrors)}).Count)
  Nodes not audited            : $($NodeCollection.Where({$_.Audited -ne $True -and $_.Audited -ne $Null}).Count)
  ----
  Total nodes audited          : $($NodeCollection.Where({$_.Audited -eq $True}).Count)
"@;

# The total time taken
$TimeBlock = @"
Total time taken               : $($TS.ToString().Split(".")[0])
"@

# Write out to screen
Write-Host "";
Write-Host "------------------------------------------";
Write-Host "Network probe" -ForegroundColor Yellow;
Write-Host $NetworkBlock;
Write-Host "";
Write-Host "Machine Audit" -ForegroundColor Yellow;
Write-Host $AuditBlock;
Write-Host "";
Write-Host $TimeBlock -ForegroundColor Magenta;
Write-Host "------------------------------------------";

# Write out to disk
$FileStatusBlock = @"
Network probe
$NetworkBlock

Machine Audit
$AuditBlock

$TimeBlock
"@

Set-Content ".\NetworkAuditStatistics.txt" -Value $FileStatusBlock;
}