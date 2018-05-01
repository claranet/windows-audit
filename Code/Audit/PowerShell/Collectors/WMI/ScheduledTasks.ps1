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

# Build our CMD
$SchtasksCmd = 'cmd /v /c SET COUNTER=0 & for /f "tokens=*" %f in (''schtasks /query /v /fo csv'') do (SET _CURR=%f & SET _CURR=!_CURR:^"=##! & reg add HKEY_LOCAL_MACHINE\SOFTWARE\ClaranetSchtasks /v !COUNTER! /t REG_SZ /d "!_CURR!" & SET /A COUNTER+=1)';

# Execute our CMD
$Process = Invoke-WmiMethod -ComputerName $Target -Credential $Credential -Class "Win32_process" -Name "Create" -ArgumentList $SchtasksCmd;

# Wait while our process runs
$InlineQuery = "SELECT * FROM WIN32_PROCESS WHERE PROCESSID='$($Process.ProcessID)'";
while ($(try{(Get-WmiObject -ComputerName $Target -Credential $Credential -Query $InlineQuery) -ne $Null}catch{$False})) {
    Start-Sleep -Seconds 2;
}

# Ok now spin up a standard registry provider
$RegProvider = Get-WmiObject -ComputerName $Target -Credential $Credential -List "StdRegProv" -Namespace "root\default";

# Declare some registry helper variables
$HKLM = [UInt32]"0x80000002";
$STKey = "SOFTWARE\ClaranetSchtasks";

# Enumerate all the key value pairs and get the data we're after
$ScheduledTasksData = @($($RegProvider.EnumValues($HKLM,$STKey).sNames | Sort {[Int]$_} | %{$Name = $_
    if ($Name -eq "0") {
        $ScheduledTasksHeader = $RegProvider.GetStringValue($HKLM,$STKey,$Name).sValue.Replace("##",'"');
    } else {
        $RegProvider.GetStringValue($HKLM,$STKey,$Name).sValue.Replace("##",'"');
    }
}));

# Delete the key we created
[Void]($RegProvider.DeleteKey($HKLM,$STKey));

# Rehydrate the data
$HydratedData = @($ScheduledTasksHeader,$ScheduledTasksData) | ConvertFrom-Csv | ?{$_.HostName -ne "HostName"};

# Now parse the data as normal
$ScheduledTasksOutput = $(@($HydratedData | %{
    [PSCustomObject]@{
        MachineIdentifier        = $MachineIdentifier;
        Name                     = $_.TaskName;
        Enabled                  = $(if ($_."Scheduled Task State" -eq "Enabled"){$True}else{$False});
        NextRunTime              = $_."Next Run Time";
        Status                   = $_."Status";
        LogonMode                = $_."Logon Mode";
        LastRunTime              = $_."Last Run Time";
        LastResult               = $_."Last Result";
        Author                   = $_."Author";
        TaskToRun                = $_."Task To Run";
        StartIn                  = $_."Start In";
        Comment                  = $_."Comment";
        IdleTime                 = $_."Idle Time";
        PowerManagement          = $_."Power Management";
        RunAsUser                = $_."Run As User";
        DeleteIfNotRescheduled   = $_."Delete Task If Not Rescheduled";
        StopIfOverrun            = $_."Stop Task If Runs X Hours and X Mins";
        ScheduleType             = $_."Schedule Type";
        StartTime                = $_."Start Time";
        StartDate                = $_."Start Date";
        EndDate                  = $_."End Date";
        Days                     = $_."Days";
        Months                   = $_."Months";
        RepeatEvery              = $_."Repeat: Every";
        RepeatUntil              = $_."Repeat: Until: Time";
        RepeatUntilDuration      = $_."Repeat: Until: Duration";
        RepeatStopIfStillRunning = $_."Repeat: Stop If Still Running";
    }
}));

# And return the data
return $ScheduledTasksOutput;