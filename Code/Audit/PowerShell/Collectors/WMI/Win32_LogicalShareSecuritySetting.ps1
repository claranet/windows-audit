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

# Get the goods
return @($(Get-WMIObject -ComputerName $Target -Credential $Credential -Class "Win32_Share" | Select -Property * | %{

    # Get the share from the pipeline
    $Share = $_;

    # Clean up the share name as some versions of WMI return the full name
    if ($Share.Name.Contains("\")) {
        $ShareLookupName = $Share.Name.Split("\")[-1];
    }
    else {
        $ShareLookupName = $Share.Name;
    }

    # Get the permissions object and our ACL object for return
    $PermissionsObject = Get-WMIObject -ComputerName $Target -Credential $Credential -Class "Win32_LogicalShareSecuritySetting" -Filter "name='$($ShareLookupName)'";

    # If there is no entry in this class; it's a default share
    if ($PermissionsObject) {
        try {
            # Get the security descriptor
            $SecurityDescriptor = $PermissionsObject.GetSecurityDescriptor().Descriptor;

            # Enumerate the ACEs in the descriptor
            $SecurityDescriptor.DACL | %{

                # Grab the ACE from the pipeline
                $ACE = $_;

                # Get the properties we want
                $UserName = $(
                    If ($ACE.Trustee.Name -eq $Null) {
                        $ACE.Trustee.SIDString;
                    }
                    ElseIf ($ACE.Trustee.Domain -ne $Null) {
                        "$($ACE.Trustee.Domain)\$($ACE.Trustee.Name)";
                    }
                    Else {
                        $ACE.Trustee.Name;
                    }
                );

                # Add to our collection of ACLs
                $FSAR = New-Object Security.AccessControl.FileSystemAccessRule($UserName, $ACE.AccessMask, $ACE.AceType);

                # Return our object to the pipeline
                $(New-Object PSCustomObject -Property @{
                    MachineIdentifier = $MachineIdentifier;
                    ShareName         = $Share.Name;
                    FileSystemRights  = $FSAR.FileSystemRights.ToString();
                    AccessControlType = $FSAR.AccessControlType.ToString();
                    IdentityReference = $FSAR.IdentityReference.ToString();
                    IsInherited       = $FSAR.IsInherited.ToString();
                    InheritanceFlags  = $FSAR.InheritanceFlags.ToString();
                    PropagationFlags  = $FSAR.PropagationFlags.ToString();
                });
            }
        }
        catch {
        }
    }
}));