[CmdletBinding()]
Param(
    # Guid for matching back to the correc machine
    [Parameter(Mandatory=$True)]
    [ValidateScript({$_ -Match "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"})]
    [String]$ID
)

# Set EAP
$ErrorActionPreference = "Stop";

# Get our return array sorted
$UpdatesList = @();

# Get a new ordered hash in place so we can add values easily
$Hash = @{
    MachineIdentifier   = $ID;
    Caption             = $Null;
    CSName              = $Null;
    Description         = $Null;
    FixComments         = $Null;
    HotFixID            = $Null;
    InstallDate         = $Null;
    InstalledBy         = $Null;
    InstalledOn         = $Null;
    Name                = $Null;
    ServicePackInEffect = $Null;
    Status              = $Null;
};
        
# Enumerate the output from wmic qfe - not to CSV as some updates contain invalid XSLT chars
ForEach ($Update in $(wmic qfe list /format:list | ?{$_})) {
    switch -Wildcard ($Update){
        "Caption*"             {$Hash.Caption             = ($Update -Split "=")[1];Break}
        "CSName*"              {$Hash.CSName              = ($Update -Split "=")[1];Break}
        "Description*"         {$Hash.Description         = ($Update -Split "=")[1];Break}
        "FixComments*"         {$Hash.FixComments         = ($Update -Split "=")[1];Break}
        "HotFixID*"            {$Hash.HotFixID            = ($Update -Split "=")[1];Break}
        "InstallDate*"         {$Hash.InstallDate         = ($Update -Split "=")[1];Break}
        "InstalledBy*"         {$Hash.InstalledBy         = ($Update -Split "=")[1];Break}
        "InstalledOn*"         {$Hash.InstalledOn         = ($Update -Split "=")[1];Break}
        "Name*"                {$Hash.Name                = ($Update -Split "=")[1];Break}
        "ServicePackInEffect*" {$Hash.ServicePackInEffect = ($Update -Split "=")[1];Break}
        "Status**"             {
            $Hash.Status = ($Update -Split "=")[1];
            $UpdatesList += $(New-Object PSCustomObject -Property $Hash);
            Break;
        }
    }
}
    
# And return our array
return ,$UpdatesList;