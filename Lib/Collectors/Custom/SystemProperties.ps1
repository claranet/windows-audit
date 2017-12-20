[CmdletBinding()]
Param(
    # Guid for matching back to the correc machine
    [Parameter(Mandatory=$True)]
    [ValidateScript({$_ -Match "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"})]
    [String]$ID
)

# Set EAP
$ErrorActionPreference = "Stop";

# Get an array to hold our system properties (easier translation later)
$SystemProperties = @();

# Set our fallback location and enumerate all the network adapters that have DHCP enabled
$Location = "On-Prem";
Get-WmiObject -Class "Win32_NetworkAdapterConfiguration" -Filter "IPEnabled = 'True' AND DHCPEnabled ='True'" | %{
    # Get the reg path into a variable for legibility
    $RegPath = "HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\$($_.SettingID)";

    # Get the DHCP options set
    $DHCP = Get-ItemProperty -Path $RegPath -Name DhcpInterfaceOptions -ErrorAction SilentlyContinue;

    # Check for the magic Azure only DHCP option
    if ($DHCP.DHCPInterfaceOptions -contains 245) {
        $Location = "Azure";
        break;
    }
}

# Build a new PSCustomObject and return it
$SystemProperties += $(New-Object PSCustomObject -Property @{
    MachineIdentifier = $ID;
    PowerShellVersion = $PSVersionTable.PSVersion.ToString();
    DotNetVersion     = [System.Runtime.InteropServices.RuntimeEnvironment]::GetSystemVersion();
    Location          = $Location;
});

# And return
return ,$SystemProperties;