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

# Ok to start with let's get a list of processes from the target
$ProcessQuery = "SELECT * FROM WIN32_Process";
$Processes = Get-WmiObject -ComputerName $Target -Credential $Credential -Query $ProcessQuery;

# Build our CMD
$NetstatCmd = "cmd /v /c SET COUNTER=0 & for /f ""tokens=*"" %f in ('netstat -ano') do (reg add HKEY_LOCAL_MACHINE\SOFTWARE\Claranet /v !COUNTER! /t REG_SZ /d ""%f"" & SET /A COUNTER+=1)";

# Execute our CMD
$Process = Invoke-WmiMethod -ComputerName $Target -Credential $Credential -Class "Win32_process" -Name "Create" -ArgumentList $NetstatCmd;


# Wait while our process runs
$InlineQuery = "SELECT * FROM WIN32_PROCESS WHERE PROCESSID='$($Process.ProcessID)'";
while ($(try{(Get-WmiObject -ComputerName $Target -Credential $Credential -Query $InlineQuery) -ne $Null}catch{$False})) {
    Start-Sleep -Seconds 2;
}

# Ok now spin up a standard registry provider
$RegProvider = Get-WmiObject -ComputerName $Target -Credential $Credential -List "StdRegProv" -Namespace "root\default";

# Declare some registry helper variables
$HKLM = [UInt32]"0x80000002";
$NSKey = "SOFTWARE\Claranet";

# Enumerate all the key value pairs and get the data we're after
$NetstatOutput = $($RegProvider.EnumValues($HKLM,$NSKey).sNames | %{
    $RegProvider.GetStringValue($HKLM,$NSKey,$_).sValue;
}) | ?{
    $_ -notlike "*Proto*Local Address*Foreign Address*State*PID*" -and 
    $_ -notlike "*Active Connections*"
};

# Delete the key we created
[Void]($RegProvider.DeleteKey($HKLM,$NSKey));

# Now parse the data as normal
$ConnectionInformation = @();
$NetstatOutput | ?{$_.Contains("ESTABLISHED") -or $_.Contains("CLOSE_WAIT")} | %{

    # Ok get the netstat row into an object to process
    $Connection = $_;

    # Split up on and dedupe spaces
    $Properties = $Connection.Split(" ") | ?{$_};

    # Get the process object from the PID
    $ProcessObject = $Processes | ?{$_.ProcessID -eq $Properties[-1]};

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
        MachineIdentifier  = $MachineIdentifier;
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
return $ConnectionInformation;