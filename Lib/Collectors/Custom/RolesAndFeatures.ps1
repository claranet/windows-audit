[CmdletBinding()]
Param(
    # Guid for matching back to the correc machine
    [Parameter(Mandatory=$True)]
    [ValidateScript({$_ -Match "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"})]
    [String]$ID
)

# Set EAP
$ErrorActionPreference = "Stop";

# Get the OS version
$OSVersion = Get-WMIObject "Win32_OperatingSystem" | Select -ExpandProperty Caption;

# Check if Server or Workstation here as this is entirely a Server only check
if ($OSVersion.ToLower().Contains("server")) {

    # Now, we need to do a check here to see if we're on 2003
    if ($OSVersion.Contains("2003")) {
        
        # 2003 requires a different capture method; Get the components from the registry
        $Components = @(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\Oc Manager\Subcomponents");
        
        # Let's check and see if we're x64 and add to the internal collection
        if ($env:PROCESSOR_ARCHITECTURE.Contains("64")) {
            $Components += @(Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Setup\Oc Manager\Subcomponents");
        }

        # Get the roles and features data
        $RolesAndFeatures = @(
            $Components | Get-Member -MemberType NoteProperty | %{ 
                if ($_.Name -notlike "PS*") {
                    [PSCustomObject]@{
                        MachineIdentifier = $ID;
                        MachineVersion    = "2003";
                        DisplayName       = $_.Name;
                        Name              = $_.Name;
                        FeatureType       = $Null;
                        Path              = $Components.PSPath;
                        Subfeatures       = $Null;
                        Installed         = [Bool]($Components.$($_.Name));
                    };
                };
            };
        );
    }

    # 2008 R2 again requires a custom method to get the information we need
    elseif ($OSVersion.Contains("2008") -and $OSVersion -notlike "*R2*") {
        
        # Kill instances of mmc.exe as these will interfere with our search
	try {
        	[Void](Invoke-Expression "taskkill /f /im mmc.exe");
	}
	catch {}
        
        # Servermanagercmd.exe is the 2008 RTM way of getting roles/features
        $SMCMD = Invoke-Expression "servermanagercmd -q";
        
        # Get the roles and features data
        $RolesAndFeatures = @(  
            $SMCMD | %{
                # Get the line containing what we want
                $Line = $_;
                
                # Work out whether it's the right type of line
                if ($Line.Contains("[X]") -or $Line.Contains("[ ]")) {
                
                    # Find out if it's installed or not
                    if ($Line.Contains("[X] ")) {
                        # Yes it is installed, remove the tickbox
                        $Line = $Line.Replace("[X] ","").Trim();
                        $Installed = $True;      
                    }
                    else {
                        # No it is not installed, remove the tickbox
                        $Line = $Line.Replace("[ ] ","").Trim();
                        $Installed = $False;
                    }
                            
                    # Set the prop values
                    $DisplayName = $Line.Split("[")[0].Trim();
                    $Name = $Line.Split("[")[1].Trim().TrimEnd("]");
                    
                    # Throw the object out
                    [PSCustomObject]@{
                        MachineIdentifier = $ID;
                        MachineVersion    = "2008 R1";
                        DisplayName       = $DisplayName;
                        Name              = $Name;
                        FeatureType       = $Null;
                        Path              = $Null;
                        Subfeatures       = $Null;
                        Installed         = $Installed;
                    };
                }
            }
        );
    }

    # This is the generic way we can get server roles/features from 2008 R2>
    else {
        
        # Kill instances of mmc.exe and ServerManager.exe as these will interfere with our search
	try {
        	[Void](Invoke-Expression "taskkill /f /im mmc.exe");
	}
	catch {}
	
	try {
        	[Void](Invoke-Expression "taskkill /f /im ServerManager.exe");
	}
	catch {}

        # Import the servermanager module for the Get-WindowsFeature cmdlet
        Import-Module ServerManager;
        $RolesAndFeatures = $(Get-WindowsFeature | Select DisplayName,Name,FeatureType,Path,Subfeatures,Installed | %{
            [PSCustomObject]@{
                MachineIdentifier = $ID;
                MachineVersion    = "2008 R2+";
                DisplayName       = $_.DisplayName;
                Name              = $_.Name;
                FeatureType       = $_.FeatureType;
                Path              = $_.Path;
                Subfeatures       = $_.SubFeatures;
                Installed         = $_.Installed;
            };
        });
    }

};

# And return the goods
return ,$RolesAndFeatures;