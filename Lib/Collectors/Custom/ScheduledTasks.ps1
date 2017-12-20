[CmdletBinding()]
Param(
    # Guid for matching back to the correc machine
    [Parameter(Mandatory=$True)]
    [ValidateScript({$_ -Match "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"})]
    [String]$ID
)

# Set EAP
$ErrorActionPreference = "Stop";

# Start the scheduled tasks service prior to checking
Get-Service "Schedule" | Start-Service -ErrorAction SilentlyContinue;

# Parse schtasks.exe for maximum compatibility
$ScheduledTasks = $(schtasks /query /v /fo csv | ConvertFrom-Csv | %{
    [PSCustomObject]@{
        MachineIdentifier        = $ID;
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
});

# And return
return ,$ScheduledTasks;