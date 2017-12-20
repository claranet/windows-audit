[CmdletBinding()]
Param(
    # Guid for matching back to the correc machine
    [Parameter(Mandatory=$True)]
    [ValidateScript({$_ -Match "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"})]
    [String]$ID
)

# Set EAP
$ErrorActionPreference = "Stop";

# Get an object to hold our output
$IISWebSites = @();

# Open the reg key and get the IIS version
try {
    [Decimal]$IISVersion = ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp" | Select -expandproperty VersionString) -Split " ")[1];
}
catch {
    # Ok no IIS
    return $IISWebSites;
}

if ($IISVersion -ge 8) {
    
    [Void](Import-Module WebAdministration -DisableNameChecking);
    
    # New PSCustomObject
    $IISWebSites += $(Get-WebSite | %{

        # Grab the site from the pipeline
        $Site = $_;
        
        # Grab the app pool info
        $ApplicationPool = Get-ChildItem "IIS:\AppPools" | ?{$_.Name -eq $Site.applicationPool} | Select -First 1;

        # Create the new pipe object
        New-Object PSCustomObject -Property @{
            MachineIdentifier                    = $ID;
            IISVersion                           = $IISVersion;
            Type                                 = "SITE";
            Name                                 = $Site.Name;
            ID                                   = $Site.ID;
            State                                = $Site.State;
            PhysicalPath                         = $Site.PhysicalPath;
            Bindings                             = $(($Site.Bindings.Collection | %{"P=$($_.Protocol)|B=$($_.BindingInformation)|S=$($_.SSLFlags)"}) -Join "##");
            ApplicationPoolName                  = $Site.applicationPool;
            ApplicationPoolState                 = $ApplicationPool.State;
            ApplicationPoolIdentityType          = $ApplicationPool.processModel.identityType;
            ApplicationPoolUser                  = $ApplicationPool.processModel.userName;
            ApplicationPoolManagedPipelineMode   = $ApplicationPool.managedPipelineMode
            ApplicationPoolManagedRuntimeVersion = $ApplicationPool.managedRuntimeVersion
            ApplicationPoolStartMode             = $ApplicationPool.startMode;
            ApplicationPoolAutoStart             = $ApplicationPool.autoStart;
        }
    });
}

# IIS 7 onwards can use Appcmd (most compatible)
if ($IISVersion -gt 7 -and $IISVersion -lt 8) {

    # Get the Sites XML
    [Xml]$SiteXml = & "C:\windows\system32\inetsrv\appcmd.exe" "list" "site" "/xml";
    $SitesList    = $SiteXml.DocumentElement.Site | Select -Property *;

    # Get the Apps XML
    [Xml]$AppsXml = & "C:\windows\system32\inetsrv\appcmd.exe" "list" "app" "/xml";
    $AppsList     = $AppsXml.DocumentElement.APP | Select -Property *;

    # Get the Application Pools
    [Xml]$PoolXml = & "C:\windows\system32\inetsrv\appcmd.exe" "list" "apppool" "/xml";
    $PoolList     = $PoolXml.DocumentElement.APPPOOL | Select -Property *;

    # Get the Virtual Directories list
    [Xml]$VdirXml = & "C:\windows\system32\inetsrv\appcmd.exe" "list" "vdirs" "/xml";
    $VdirList     = $VdirXml.DocumentElement.VDIR | Select -Property *;

    # Enumerate and check each site to get the data
    $SitesList | %{

        # Get the site object
        $Site = $_;
            
        # Get the physical path for the site
        $PhysicalPath = & "C:\windows\System32\Inetsrv\appcmd.exe" "list" "app" "$($Site."SITE.NAME")/" "/text:[path='/'].physicalPath";
        $PhysicalPath = ($PhysicalPath -replace "%SystemDrive%",$Env:SystemDrive) -replace "%SystemRoot%",$env:SystemRoot;

        # Get the application pool information
        $ApplicationPoolName       = $AppsList | ?{$_."SITE.NAME" -eq $Site."SITE.NAME"} | Select -ExpandProperty "APPPOOL.NAME";
        $ApplicationPoolProperties = $PoolList | ?{$_."APPPOOL.NAME" -eq $ApplicationPoolName};
        [String[]]$AppPoolTextProperties = & "C:\windows\system32\inetsrv\appcmd.exe" "list" "apppool" "$ApplicationPoolName" "/text:*";
            
        # New PSCustomObject
        $IISWebSites += $(New-Object PSCustomObject -Property @{
            MachineIdentifier                    = $ID;
            IISVersion                           = $IISVersion;
            Type                                 = $Site.Name;
            Name                                 = $Site."SITE.NAME";
            ID                                   = $Site."SITE.ID";
            State                                = $Site.state;
            PhysicalPath                         = $PhysicalPath;
            Bindings                             = $Site.bindings;
            ApplicationPoolName                  = $ApplicationPoolName;
            ApplicationPoolState                 = $ApplicationPoolProperties.state;
            ApplicationPoolIdentityType          = ((($AppPoolTextProperties | ?{$_ -like "*identityType*"}) -Split ":")[1]) -Replace """","";
            ApplicationPoolUser                  = ((($AppPoolTextProperties | ?{$_ -like "*userName*"}) -Split ":")[1]) -Replace """","";
            ApplicationPoolManagedPipelineMode   = $ApplicationPoolProperties.PipelineMode;
            ApplicationPoolManagedRuntimeVersion = $ApplicationPoolProperties.RuntimeVersion;
            ApplicationPoolStartMode             = ((($AppPoolTextProperties | ?{$_ -like "*startMode*"}) -Split ":")[1]) -Replace """","";
            ApplicationPoolAutoStart             = $([Bool](((($AppPoolTextProperties | ?{$_ -like "*autoStart*"}) -Split ":")[1]) -Replace """",""));
        });
    };

    # Enumerate the virtual directory list and get the data
    $VdirList | %{

        # Get the vdir object
        $Vdir = $_;

        # Replace the physical path system variable strings
        $PhysicalPath = $Vdir.physicalPath.Replace("%SystemDrive%",$Env:SystemDrive).Replace("%SystemRoot%",$env:SystemRoot);

        # Check to see whether this is the default vdir for an app
        if ($($IISWebSites | ?{$_.PhysicalPath -eq $PhysicalPath -and $_.Type -eq "SITE"}) -eq $Null) {
                   
            # New PSCustomObject
            $IISWebSites += $(New-Object PSCustomObject -Property @{
                MachineIdentifier                    = $ID;
                IISVersion                           = $IISVersion;
                Type                                 = $Vdir.Name;
                Name                                 = ($Vdir."VDIR.NAME" -split "/")[-1];
                ID                                   = ($Vdir."APP.NAME" -split "/")[0];
                State                                = $Null;
                PhysicalPath                         = $PhysicalPath;
                Bindings                             = $Null;
                ApplicationPoolName                  = $Null;
                ApplicationPoolState                 = $Null;
                ApplicationPoolIdentityType          = $Null;
                ApplicationPoolUser                  = $Null;
                ApplicationPoolManagedPipelineMode   = $Null;
                ApplicationPoolManagedRuntimeVersion = $Null;
                ApplicationPoolStartMode             = $Null;
                ApplicationPoolAutoStart             = $Null;
            });
        }
    };
}

# IIS v5/6 use WMI
if ($IISVersion -ne $Null -and $IISVersion -lt 7) {
    
    Get-WmiObject -Namespace "root/MicrosoftIISv2" -Class IIsWebServerSetting | %{
        
        # Grab the site from the pipeline
        $Site = $_;
    
        # Grab settings from other areas
        $SiteSettings = Get-WmiObject -Namespace "root/MicrosoftIISv2" -Class IIsWebServer -Filter "Name='$($Site.Name)'" | Select -Property *;
        $AppPool      = Get-WmiObject -Namespace "root/MicrosoftIISv2" -Class IIsApplicationPoolSetting -Filter "Name='W3SVC/AppPools/$($Site.AppPoolID)'" | Select -Property *;
        $Vdir         = Get-WmiObject -Namespace "root/MicrosoftIISv2" -Class IIsWebVirtualDirSetting -Filter "Name='$($Site.Name)/root'" | Select -Property *;
            
        # Create the object we're after
        $IISWebSites += $(New-Object PSCustomObject -Property @{
            MachineIdentifier                    = $ID;
            IISVersion                           = $IISVersion;
            Type                                 = "SITE";
            Name                                 = $_.ServerComment;
            ID                                   = $Site.Name.Split("/")[1];
            State                                = $(switch($SiteSettings.ServerState){1 {"Starting"};2 {"Started"};3 {"Stopping"};4 {"Stopped"}});
            PhysicalPath                         = $Vdir.Path;
            Bindings                             = $Site.ServerBindings;
            ApplicationPoolName                  = $Site.AppPoolID;
            ApplicationPoolState                 = $(Switch($AppPool.AppPoolState){1 {"Starting"};2 {"Started"};3 {"Stopping"};4 {"Stopped"}});
            ApplicationPoolIdentityType          = $(Switch($AppPool.AppPoolIdentityType){2 {"BuiltIn"};3 {"Custom"}});
            ApplicationPoolUser                  = $AppPool.WAMUserName;
            ApplicationPoolManagedPipelineMode   = "N/A";
            ApplicationPoolManagedRuntimeVersion = "v1/2";
            ApplicationPoolStartMode             = $(Switch($AppPool.AutoShutdownAppPoolExe){$True {"OnDemand"}; $False {"AlwaysRunning"}; Default{"AlwaysRunning"}});
            ApplicationPoolAutoStart             = [Bool]($AppPool.AppPoolAutoStart);
        });
    }
}

# And return
return ,$IISWebSites;