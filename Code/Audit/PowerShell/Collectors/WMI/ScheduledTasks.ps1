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

# Micro inline function for rehydrating csv rows
Function Rehydrate-CsvRow {
    Param($Row)
    # Split the line on the comma separator
    $Split = $Row.Split(",");

    # Enumerate, rehydrate, join and return
    return $(($Split | %{"""$($_)"""}) -join ",");
}


# Build our CMD
$SchtasksCmd = "cmd /v /c SET COUNTER=0 & for /f ""tokens=*"" %f in ('schtasks /query /v /fo csv') do (reg add HKEY_LOCAL_MACHINE\SOFTWARE\ClaranetSchtasks /v !COUNTER! /t REG_SZ /d %f & SET /A COUNTER+=1)";

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
$CurrentHeaderRow = $Null;
$ScheduledTasksData = $($RegProvider.EnumValues($HKLM,$STKey).sNames | Sort {[Int]$_} | %{$Name = $_
    
    # Grab the value from the reg provider
    $Row = $RegProvider.GetStringValue($HKLM,$STKey,$Name).sValue;
    
    # If the value contains header info, switch accordingly
    if ($Row.Contains("HostName,TaskName,")) {
        
        # Ok let's check if we need to flush to the pipeline
        if ($CurrentHeaderRow -ne $Null -and $CurrentDataRows.Count -gt 0) {
            @($CurrentHeaderRow,$CurrentDataRows) | ConvertFrom-Csv;
        } 

        # Flush our variables and set the new header row
        $CurrentHeaderRow = $(Rehydrate-CsvRow -Row $Row);
        $CurrentDataRows  = @();

    } else {
        $CurrentDataRows += $(Rehydrate-CsvRow -Row $Row);
    }
});

# Delete the key we created
[Void]($RegProvider.DeleteKey($HKLM,$NSKey));

# Now parse the data as normal
$ScheduledTasksOutput = $(@($ScheduledTasksData | %{
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