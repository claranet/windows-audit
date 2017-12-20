[Cmdletbinding()]
Param(
    # The PSCredential to be used for the connection
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [PSCredential]$PSCredential,

    # The server object passed from the network scanning job
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [PSCustomObject]$Node,

    # The fully qualified path to the working directory
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String]$WorkingDirectory
)

# Set EAP
$ErrorActionPreference = "Stop";

# Quick check and make sure we have what we need
if ($Node.Hostname) {
    $Targethost = $Node.Hostname;
}
elseif ($Node.IPAddress) {
    $Targethost = $Node.IPAddress;
}
else {
    $Node.Status = "Node has no IPAddress or Hostname";
    return $Node;
}

# Check see if the XML directory exists and create if not
$XMLDirectory = "$WorkingDirectory\Output";
if (!(Test-Path $XMLDirectory)) {
    [Void](New-Item $XMLDirectory -ItemType Directory);
}

# Get all our scan scripts into an array of objects
$ScriptDirectory = "$WorkingDirectory\Lib\Collectors";
$AuditSections = $(Get-ChildItem $ScriptDirectory -Recurse "*.ps1" | %{
    [PSCustomObject]@{
        SectionName  = $_.BaseName;
        ScriptBlock  = [ScriptBlock]::Create($(Get-Content $_.FullName | Out-String));
        Completed    = $False;
        RetryCount   = 0;
    }
});

# Build the errors object
Add-Type -AssemblyName "System.Data";
$ErrorsTable = New-Object System.Data.DataTable;
"MachineIdentifier","Section","TryCount","Error" | %{
    $ErrorsTable.Columns.Add($(New-Object System.Data.DataColumn $_,([string])));
}

# Build the audit data object
$AuditData = New-Object PSCustomObject;

# Now we have to use a while loop to make sure we capture all the retries
while ($AuditSections.Where({$_.RetryCount -le 3 -and $_.Completed -eq $False}).Count -gt 0) {

    # Enumerate the audit sections and get the data together
    $AuditSections.Where({$_.RetryCount -le 3 -and $_.Completed -eq $False}).ForEach({

        # Get the current section from the pipeline
        $CurrentSection = $_;

        # Trapped so we don't blow the whole lot
        try {
            # Attempt to get the data
            $CurrentData = Invoke-Command -ComputerName $Targethost -ScriptBlock $CurrentSection.ScriptBlock -Credential $PSCredential -Authentication Negotiate -ArgumentList $Node.ID; 
            
            # Null check so we dont bomb out with Get-Member
            if ($CurrentData) {
                # Ok we want to check and see whether we got a dodgy hashtable back
                if (($CurrentData | Gm | Select -ExpandProperty TypeName -First 1).Contains("Hashtable")) {
                        # Get a holding array sorted
                        [System.Collections.ArrayList]$HoldingArray = @();
                    
                        # Enumerate the current data and spin out PSCustomObjects for each one
                        $CurrentData.GetEnumerator() | %{
                            [Void]($HoldingArray.Add($(New-Object PSCustomObject -Property $_)));
                        }
                    
                        # Explicitly splat the original variable with the new one to avoid data type confusion
                        $CurrentData = $Null;
                        $CurrentData = $HoldingArray;            
                }
            }
    
            # Add the result to the audit object
            $AuditData | Add-Member -MemberType NoteProperty -Value $CurrentData -Name $CurrentSection.SectionName;

            # Set the current section to completed
            $AuditSections.Where({$_.SectionName -eq $CurrentSection.SectionName},"First").ForEach({
                $_.Completed = $True;
            });

            # Quick gap let the machine catch its breath
            Start-Sleep -Milliseconds 50;
        }
        catch {
            # Catch the exception
            $E = $_;

            # set the retries on this object
            $AuditSections.Where({$_.SectionName -eq $CurrentSection.SectionName},"First").ForEach({
                $_.RetryCount = $($CurrentSection.RetryCount + 1);
            });

            # Add the error to the error list object
            $ErrorRow                   = $ErrorsTable.NewRow();
            $ErrorRow.MachineIdentifier = $Node.ID;
            $ErrorRow.Section           = $CurrentSection.SectionName;
            $ErrorRow.TryCount          = $CurrentSection.RetryCount;
            $ErrorRow.Error             = $E.Exception.Message;
            $ErrorsTable.Rows.Add($ErrorRow);
        }
    });
}

# Add the errors to the object
$AuditData | Add-Member -MemberType NoteProperty -Name Errors -Value $ErrorsTable;

# Export the XML
$XmlOutputFile = "$XMLDirectory\$Targethost.xml";
Export-Clixml -InputObject $AuditData -Path $XmlOutputFile -Force;

# Prepare the error string for return
[System.Collections.ArrayList]$ErrorArray = @();
$ErrorsTable | %{
    [Void]($ErrorArray.Add($("[$(Get-Date -f "ddMMyy HH:mm:ss")][Audit Error - $($_.Section)]: $($_.Error)")));
};

# Update the node object
$Node.Audited     = $True;
$Node.Completed   = $($ErrorsTable.Rows.Count -eq 0);
$Node.AuditErrors = $($ErrorArray -join "`r`n");

# Return the node object
return $Node;