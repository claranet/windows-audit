[Cmdletbinding()]
Param(
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String]$MachineIdentifier
)

return $(Get-WMIObject -Class "Win32_OperatingSystem" | Select -ExpandProperty Caption);