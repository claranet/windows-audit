[CmdletBinding()]
Param(
    # Guid for matching back to the correc machine
    [Parameter(Mandatory=$True)]
    [ValidateScript({$_ -Match "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"})]
    [String]$ID
)

# Set EAP
$ErrorActionPreference = "Stop";

# Custom SQl query function to avoid management tools dependency
Function Invoke-SQLQuery {
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$ServerName,

        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$Database,

        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$Query
    )

    # Get our return table initialised
    $Datatable = New-Object System.Data.DataTable;
    
    # Get our connection sorted out
    $Connection = New-Object System.Data.SQLClient.SQLConnection;
    $Connection.ConnectionString = "server='$ServerName';database='$Database';trusted_connection=true;";
    $Connection.Open();

    # Get the SQL command ready to execute
    $Command = New-Object System.Data.SQLClient.SQLCommand;
    $Command.Connection = $Connection;
    $Command.CommandText = $Query;

    # Execute the reader command and load the datatable we created earlier
    $Reader = $Command.ExecuteReader();
    $Datatable.Load($Reader);

    # Close off the connection
    $Connection.Close();
    
    # And return
    return $Datatable;
}

# Get our output object sorted
$SQLServerDatabases = @();

# Check to see if the SQL server regkey exists
if (Test-Path "HKLM:\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL") {
    
    # Ok let's declare some objects to hold our data
    $SQLRegInstances      = @();
    $SQLWMIInstances      = @();
    $SQLInstances         = @();

    # Get SQL reg instances
    $KeyInfo = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Microsoft SQL Server" -Name "InstalledInstances" -ErrorAction SilentlyContinue;
    $KeyInfo.InstalledInstances | %{
        $SQLRegInstances += $(New-Object PSCustomObject -Property @{
            Name = $_;
            Version = "2000";
        });
    }

    # Get all the SQL instances from WMI
    "","10","11","12","13","14" | %{
        $IID = $_;
        Get-WmiObject -Namespace "root\Microsoft\SqlServer\ComputerManagement$IID" -Class "ServerSettings" -ErrorAction SilentlyContinue | %{
            $SQLWMIInstances += $(New-Object PSCustomObject -Property @{
                Name    = $_.InstanceName;
                Version = $(Switch($IID){""{"2005"};"10"{"2008"};"11"{"2012"};"12"{"2014"};"13"{"2016"};"14"{"2017"}});
            });
        }
    }

    # Ok we need to do some juggling here, both 2000 and 2008/12 instances show up in the registry
    $SQLRegInstances = $SQLRegInstances | ?{$($SQLWMIInstances | Select -ExpandProperty Name) -notcontains $_.Name};
            
    # Coalesce our results down
    $SQLInstances += $SQLRegInstances;
    $SQLInstances += $SQLWMIInstances;
            
    # Enumerate the instances and get the data
    $SQLInstances | ?{$_ -and $_.Name} | %{
    
        # Get the instance name
        $InstanceName = $_.Name;
        $InstanceVersion = $_.Version;
        
        # If the instance is the default we need to connect differently
        if ($InstanceName -eq "MSSQLSERVER") {
            $InstanceConnectionIdentifier = $env:computername;
        }
        else {
            $InstanceConnectionIdentifier = $env:computername + "\" + $InstanceName;
        }
        
        # Get the list of databases for this instance
        try {
            $Databases = Invoke-SQLQuery -Server $InstanceConnectionIdentifier -Database Master -Query "select name from sys.databases";
    
            # Enumerate the database list and get the sp_helpdb info
            $Databases | %{
            
                # Get the SP_HELPDB object
                $DatabaseName = $_.Name;
                $DB = Invoke-SQLQuery -ServerName $InstanceConnectionIdentifier -Database Master -query "EXEC SP_HELPDB '$DatabaseName'";
        
                # Parse and add to the DBInfoCollection
                $SQLServerDatabases += $(New-Object PSCustomObject -Property @{
                    MachineIdentifier    = $ID;
                    InstanceName         = $InstanceName;
                    ConnectionIdentifier = $InstanceConnectionIdentifier
                    Name                 = $DB.name;
                    Size                 = $(if($DB.db_size){$DB.db_size.ToString().Trim()});
                    Owner                = $DB.owner;
                    DBID                 = $DB.dbid;
                    CreatedDate          = $(if ($DB.created) {[Datetime]$DB.created});
                    Status               = $DB.status;
                    CompatibilityLevel   = $DB.compatibility_level;
                });
            }
        }
        catch {
            # Not really fussed tbh, we know whether we can access the instance from the SQLServerInstances object
        }
    }
};

# And return
return ,$SQLServerDatabases;