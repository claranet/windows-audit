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

# Get our registry provider instance and authenticate against the target
$RegProvider = Get-WmiObject -ComputerName $Target -Credential $Credential -List "StdRegProv" -Namespace "root\default";

# Declare some helper variables and an array to hold our applications
$HKLM = [UInt32]"0x80000002";
$UKey = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
$Applications = New-Object System.Collections.ArrayList;

# Pipeline to stream our EnumKey output
$RegProvider.EnumKey($HKLM,$UKey).sNames | %{

    # Grab the key name from the pipeline work out the subkey path
    $KeyName = $_;
    $SubKey  = $UKey + "\$KeyName";

    # Build an object we can set properties on as we go
    $Application = New-Object PSCustomObject;

    # Grab the properties from this key
    $Properties = $RegProvider.EnumValues($HKLM,$Subkey);

    # Set a bool we can reverse if blank entry
    $IsEmpty = $True;

    # Delve further into the rabbit hole using a for loop so we can index easily
    for ($I = 0; $I -le $Properties.sNames.length - 1; $I++) {

        # Grab the property name and type
        $PropertyName = $Properties.sNames[$I];
        $PropertyType = $Properties.Types[$I];

        # Check and make sure we have a name and type
        if ($PropertyName -and $PropertyType) {
            
            # Switch based on the type to get the value
            Switch($PropertyType) {
                1 { # REG_SZ
                    $PropertyValue = $RegProvider.GetStringValue($HKLM, $Subkey, $PropertyName).sValue;
                }
                2 { # REG_EXPAND_SZ
                    $PropertyValue = $RegProvider.GetExpandedStringValue($HKLM, $Subkey, $PropertyName).sValue;
                }
                3 { # REG_BINARY
                    $PropertyValue = $RegProvider.GetBinaryValue($HKLM, $Subkey, $PropertyName).sValue;
                }
                4 { # REG_DWORD
                    $PropertyValue = $RegProvider.GetDWORDValue($HKLM, $Subkey, $PropertyName).sValue;
                }
                7 { # REG_MULTI_SZ
                    $PropertyValue = $RegProvider.GetMultiStringValue($HKLM, $Subkey, $PropertyName).sValue;
                }
                11 { # REG_QWORD
                    $PropertyValue = $RegProvider.GetQWORDValue($HKLM, $Subkey, $PropertyName).sValue;
                }
                default { # Default
                    $PropertyValue = $RegProvider.GetStringValue($HKLM, $Subkey, $PropertyName).sValue;
                }
            }

            # Set to true null if garbage
            if ($PropertyValue -eq "null") {
                $PropertyValue = $Null;
            }

            # Flick our bit to say this isn't blank
            if (![String]::IsNullOrEmpty($PropertyValue)) {
                $IsEmpty = $False;
            }

            # Add the new property to the Application
            $Application | Add-Member -MemberType NoteProperty -Name $PropertyName -Value $PropertyValue;
        }
    }

    # Only add if at least one property has a value
    if (!$IsEmpty) {
        # Tag it with our machine identifier
        $Application | Add-Member -MemberType NoteProperty -Name "MachineIdentifier" -Value $MachineIdentifier;

        # And add to the collection
        [Void]($Applications.Add($Application));
    }
}

# And return
return $Applications;