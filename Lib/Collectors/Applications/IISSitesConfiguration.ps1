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
$IISConfigurationFiles = @();

# Open the reg key and get the IIS version
try {
    [Decimal]$IISVersion = ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp" | Select -expandproperty VersionString) -Split " ")[1];
}
catch {
    # Ok no IIS
    return $IISConfigurationFiles;
}

if ($IISVersion -ge 8) {
    
    [Void](Import-Module WebAdministration -DisableNameChecking);
    
    # Enumerate the output from Get-WebSite
    Get-WebSite | %{

        # Grab the site from the pipeline
        $Site = $_;
        
        # Parse our config files out
        try {
            $IISConfigurationFiles += $(Get-ChildItem -Path $Site.physicalPath -Recurse | ?{$_.Name -like "*.config"} | %{
                # PSCO to the pipeline
                New-Object PSCustomObject -Property @{
                    MachineIdentifier                    = $ID;
                    IISVersion                           = $IISVersion;
                    Name                                 = $Site.Name;
                    ID                                   = $Site.ID;
                    SitePath                             = $Site.PhysicalPath;
                    ConfigurationFileName                = $_.Name;
                    ConfigurationFilePath                = $_.FullName;
                    ConfigurationFileContent             = $(Get-Content $_.FullName | Out-String);
                }
            });
        }
        catch {
            # Ok someone has seriously borked this site
        }
    }
}

# IIS 7 onwards can use Appcmd (most compatible)
if ($IISVersion -gt 7 -and $IISVersion -lt 8) {

    # Get the Sites XML
    [Xml]$SiteXml = & "C:\windows\system32\inetsrv\appcmd.exe" "list" "site" "/xml";
    $SitesList    = $SiteXml.DocumentElement.Site | Select -Property *;

    # Enumerate and check each site to get the data
    $SitesList | %{

        # Get the site object
        $Site = $_;
            
        # Get the physical path for the site
        $PhysicalPath = & "C:\windows\System32\Inetsrv\appcmd.exe" "list" "app" "$($Site."SITE.NAME")/" "/text:[path='/'].physicalPath";
        $PhysicalPath = ($PhysicalPath -replace "%SystemDrive%",$Env:SystemDrive) -replace "%SystemRoot%",$env:SystemRoot;

        # Parse our config files out
        try {
            $IISConfigurationFiles += $(Get-ChildItem -Path $PhysicalPath -Recurse | ?{$_.Name -like "*.config"} | %{
                # PSCO to the pipeline
                New-Object PSCustomObject -Property @{
                    MachineIdentifier                    = $ID;
                    IISVersion                           = $IISVersion;
                    Name                                 = $Site."SITE.NAME";
                    ID                                   = $Site."SITE.ID";
                    SitePath                             = $PhysicalPath;
                    ConfigurationFileName                = $_.Name;
                    ConfigurationFilePath                = $_.FullName;
                    ConfigurationFileContent             = $(Get-Content $_.FullName | Out-String);
                }
            });
        }
        catch {
            # Ok someone has seriously borked this site
        }
    };
}

# IIS v5/6 use WMI
if ($IISVersion -ne $Null -and $IISVersion -lt 7) {
    
    Get-WmiObject -Namespace "root/MicrosoftIISv2" -Class IIsWebServerSetting | %{
        
        # Grab the site from the pipeline
        $Site = $_;
    
        # Grab settings from other areas
        $Vdir = Get-WmiObject -Namespace "root/MicrosoftIISv2" -Class IIsWebVirtualDirSetting -Filter "Name='$($Site.Name)/root'" | Select -Property *;
    
        # Parse our config files out
        try {
            $IISConfigurationFiles += $(Get-ChildItem -Path $Vdir.Path -Recurse | ?{$_.Name -like "*.config"} | %{
                # PSCO to the pipeline
                New-Object PSCustomObject -Property @{
                    MachineIdentifier                    = $ID;
                    IISVersion                           = $IISVersion;
                    Name                                 = $Site.ServerComment;
                    ID                                   = $($Site.Name -split "/" | Select -Last 1);
                    SitePath                             = $Vdir.Path;
                    ConfigurationFileName                = $_.Name;
                    ConfigurationFilePath                = $_.FullName;
                    ConfigurationFileContent             = $(Get-Content $_.FullName | Out-String);
                }
            });
        }
        catch {
            # Ok someone has seriously borked this site
        }
    }
}

# And return
return ,$IISConfigurationFiles;