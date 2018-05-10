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

# Build an array to hold our output
$Output = @();

# First we need to get our OS version
$OSProperties = Get-WmiObject -ComputerName $Target -Credential $Credential -Class "Win32_OperatingSystem";
$OSVersion    = [Version]($OSProperties.Version);

# Switch paths based on operating system version
if ($OSVersion.Major -lt 6) {
    # Declare some registry helper variables
    $HKLM = [UInt32]"0x80000002";
    $FeatureRegKeys = @(
        "SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\OC Manager\Subcomponents",
        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Setup\Oc Manager\Subcomponents"
    )

    # Get our registry provider instance and authenticate against the target
    $RegProvider = Get-WmiObject -ComputerName $Target -Credential $Credential -List "StdRegProv" -Namespace "root\default";

    # Enumerate the keys we need to check
    $FeatureRegKeys.ForEach({

        # Grab the reg key from the pipeline
        $FeatureRegKey = $_;
        
        # Grab the properties for this key
        $Properties = $RegProvider.EnumValues($HKLM,$FeatureRegKey);

        # Enumerate the properties in this key using for for easy indexing
        for ($I = 0; $I -le $Properties.sNames.length - 1; $I++) {

            # Grab the property name and type
            $PropertyName = $Properties.sNames[$I];
            $PropertyType = $Properties.Types[$I];

            # Check and make sure we have a name and type
            if ($PropertyName -and $PropertyType) {
            
                # Switch based on the type to get the value
                Switch($PropertyType) {
                    1 { # REG_SZ
                        $PropertyValue = $RegProvider.GetStringValue($HKLM, $FeatureRegKey, $PropertyName).sValue;
                    }
                    2 { # REG_EXPAND_SZ
                        $PropertyValue = $RegProvider.GetExpandedStringValue($HKLM, $FeatureRegKey, $PropertyName).sValue;
                    }
                    3 { # REG_BINARY
                        $PropertyValue = $RegProvider.GetBinaryValue($HKLM, $FeatureRegKey, $PropertyName).uValue;
                    }
                    4 { # REG_DWORD
                        $PropertyValue = $RegProvider.GetDWORDValue($HKLM, $FeatureRegKey, $PropertyName).uValue;
                    }
                    7 { # REG_MULTI_SZ
                        $PropertyValue = $RegProvider.GetMultiStringValue($HKLM, $FeatureRegKey, $PropertyName).sValue;
                    }
                    11 { # REG_QWORD
                        $PropertyValue = $RegProvider.GetQWORDValue($HKLM, $FeatureRegKey, $PropertyName).uValue;
                    }
                    default { # Default
                        $PropertyValue = $RegProvider.GetStringValue($HKLM, $FeatureRegKey, $PropertyName).sValue;
                    }
                }

                # Add the new property to the Application
                $Output += $([PSCustomObject]@{
                    MachineIdentifier  = $MachineIdentifier;
                    Name               = $PropertyName;
                    Type               = "Windows [NT|2000|2003] Feature";
                    Description        = $PropertyName;
                    IsInstalled        = [Bool]$PropertyValue;
                });
            }
        }

    });

} else {
    # Get the optional features
    Get-WmiObject -ComputerName $Target -Credential $Credential -Class "Win32_OptionalFeature" -ErrorAction SilentlyContinue | %{
        $Output += $([PSCustomObject]@{
            MachineIdentifier  = $MachineIdentifier;
            Name               = $_.Name;
            Type               = "Windows Server Feature";
            Description        = $_.Caption;
            IsInstalled        = [Bool]$_.InstallState;
        });
    }

    # Get all the features
    Get-WmiObject -ComputerName $Target -Credential $Credential -Class "Win32_ServerFeature" -ErrorAction SilentlyContinue | %{
        $Output += $([PSCustomObject]@{
            MachineIdentifier  = $MachineIdentifier;
            Name               = $_.Name;
            Type               = "Windows Server Role";
            Description        = $Null;
            IsInstalled        = $True;
        });
    }
}

# And return our output
return $Output;