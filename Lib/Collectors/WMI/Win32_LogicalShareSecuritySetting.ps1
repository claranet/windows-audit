[CmdletBinding()]
Param(
    # Guid for matching back to the correc machine
    [Parameter(Mandatory=$True)]
    [ValidateScript({$_ -Match "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"})]
    [String]$ID
)

# Set EAP
$ErrorActionPreference = "Stop";

# Get our return object sorted out
$SharePermissions = @();

# Enumerate the shares and get what we want
Get-WMIObject -Class "Win32_Share" | Select -Property * | %{
    
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
    $PermissionsObject = Get-WMIObject -Class "Win32_LogicalShareSecuritySetting" -Filter "name='$($ShareLookupName)'";

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

                $SharePermissions += $(New-Object PSCustomObject -Property @{
                    MachineIdentifier = $ID;
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
}

# And return
return $SharePermissions;