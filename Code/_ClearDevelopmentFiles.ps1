[Cmdletbinding()]
Param(
    [Parameter(Mandatory=$True)]
    [ValidateScript({Test-Path $_})]
    [String]$WorkspaceFolder
)

# Build the root path
$RootPath = "{0}\Code\Audit" -f $WorkspaceFolder;

# Enumerate the folders we want to clear
"Credentials","Data","Hosts","Results" | %{

    # Build the folder path
    $Folder = "{0}\{1}" -f $RootPath,$_;

    # Enumerate all the files and remove them
    Get-ChildItem -Path $Folder -Recurse | %{
        Remove-Item $_.FullName -Force;
    }
}

# Also let's remove any audit keys generated
$DownloadsFolder = "{0}\Downloads" -f $env:USERPROFILE;
Get-ChildItem $DownloadsFolder -Recurse "*.auditkey" | %{
    Remove-Item $_.FullName -Force;
};