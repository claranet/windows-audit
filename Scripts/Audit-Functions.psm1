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

# Returns a bool indicating whether the supplied string is an IPv4 address
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
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$ComputerName,
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$Script,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Int]$SerialisationDepth = 5
    )

    # Trapped to take advantage of finally block
    try {
        # Ok we need to get an object containing the properties we want
        $ScriptFileObject = Get-Item $Script;
        
        # Then tune a few properties we need
        $ScriptPath = $ScriptFileObject.Directory.FullName;
        $ShareName  = ($ScriptFileObject.BaseName -replace '[^a-zA-Z]','') + '$';
        $ScriptFile = $ScriptFileObject.Name;

        # Then we need to share the script path with the script name we parsed
        [Void](New-SMBShare -Name $ShareName -Path $ScriptPath -FullAccess "Everyone");

        # Get the command built; Unrestricted policy is for PSv2 compatibility, the scope is this execution only
        $Command = @(
            'Set-ExecutionPolicy Unrestricted -ErrorAction SilentlyContinue;',
            $('$ScriptBlock = [ScriptBlock]::Create($(Get-Content "\\{0}\{1}\{2}" | Out-String));' -f $env:COMPUTERNAME,$ShareName,$ScriptFile),
            '$AuditResult = $ScriptBlock.Invoke();',
            $('return [System.Management.Automation.PSSerializer]::Serialize($AuditResult,{0});' -f $SerialisationDepth)
        ) -Join "";

        # And get the expression ready
        $Expression = "psexec -i \\$ComputerName  cmd /c powershell -Command $Command";
        
        # Invoke the PSExec command
        $RawOutput = Invoke-Expression $Expression;

        # Clean up the output
        $RawOutput = $RawOutput -replace "PsExec v(.*) - Execute processes remotely","";
        $RawOutput = $RawOutput -replace "Copyright \(C\) (.*) Mark Russinovich","";
        $RawOutput = $RawOutput -replace "Sysinternals - www.sysinternals.com","";
        $RawOutput = $RawOutput | ?{![String]::IsNullOrEmpty($_)};
        [PSCustomObject]$Output = [System.Management.Automation.PSSerializer]::Deserialize($RawOutput);

        # And return the goods
        return $Output;
    }
    catch {
        throw $Error[0];
    }
    finally {
        [Void](Get-SMBShare -Name $ShareName -ErrorAction SilentlyContinue | Remove-SMBShare -Force);
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
    $Output = [String]::Format("[{0}] [LOCAL:{1}]: {2}",$DateStamp,$Type,$Message);
    
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

    # And write out
    Write-Host $Output -ForegroundColor $C;
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
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$Exception
    )

    # Get a datestamp sorted
    $DateStamp = Get-Date -Format "dd/MM/yy HH:mm:ss";

    # Build our message output
    $Output = [String]::Format("[{0}] [{1}] [{2}]: {3}",$DateStamp,$HostName,$EventName,$Exception);
    
    # Check if our errors file exists and create if needed
    $ErrorsFile = ".\errors.log";
    if (!(Test-Path $ErrorsFile)) {
        [Void](New-Item $ErrorsFile -ItemType File);
    }

    # Add the content to the file
    Add-Content -Path $ErrorsFile -Value $Output;
}