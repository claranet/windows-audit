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

# Return the goods
return $(Get-WMIObject -ComputerName $Target -Credential $Credential -Class "Win32_NetworkAdapterConfiguration" | Select -Property * | %{
    New-Object PSCustomObject -Property @{
        MachineIdentifier             = $MachineIdentifier;
        DHCPLeaseExpires              = $_.DHCPLeaseExpires;
        Index                         = $_.Index;
        Description                   = $_.Description;
        DHCPEnabled                   = $_.DHCPEnabled;
        DHCPLeaseObtained             = $_.DHCPLeaseObtained;
        DHCPServer                    = $_.DHCPServer;
        DNSDomain                     = $_.DNSDomain;
        DNSDomainSuffixSearchOrder    = $_.DNSDomainSuffixSearchOrder;
        DNSEnabledForWINSResolution   = $_.DNSEnabledForWINSResolution;
        DNSHostName                   = $_.DNSHostName;
        DNSServerSearchOrder          = $_.DNSServerSearchOrder;
        DomainDNSRegistrationEnabled  = $_.DomainDNSRegistrationEnabled;
        FullDNSRegistrationEnabled    = $_.FullDNSRegistrationEnabled;
        IPAddress                     = $_.IPAddress;
        IPConnectionMetric            = $_.IPConnectionMetric;
        IPEnabled                     = $_.IPEnabled;
        IPFilterSecurityEnabled       = $_.IPFilterSecurityEnabled;
        WINSEnableLMHostsLookup       = $_.WINSEnableLMHostsLookup;
        WINSHostLookupFile            = $_.WINSHostLookupFile;
        WINSPrimaryServer             = $_.WINSPrimaryServer;
        WINSScopeID                   = $_.WINSScopeID;
        WINSSecondaryServer           = $_.WINSSecondaryServer;
        ArpAlwaysSourceRoute          = $_.ArpAlwaysSourceRoute;
        ArpUseEtherSNAP               = $_.ArpUseEtherSNAP;
        Caption                       = $_.Caption;
        DatabasePath                  = $_.DatabasePath;
        DeadGWDetectEnabled           = $_.DeadGWDetectEnabled;
        DefaultIPGateway              = $_.DefaultIPGateway;
        DefaultTOS                    = $_.DefaultTOS;
        DefaultTTL                    = $_.DefaultTTL;
        ForwardBufferMemory           = $_.ForwardBufferMemory;
        GatewayCostMetric             = $_.GatewayCostMetric;
        IGMPLevel                     = $_.IGMPLevel;
        InterfaceIndex                = $_.InterfaceIndex;
        IPPortSecurityEnabled         = $_.IPPortSecurityEnabled;
        IPSecPermitIPProtocols        = $_.IPSecPermitIPProtocols;
        IPSecPermitTCPPorts           = $_.IPSecPermitTCPPorts;
        IPSecPermitUDPPorts           = $_.IPSecPermitUDPPorts;
        IPSubnet                      = $_.IPSubnet;
        IPUseZeroBroadcast            = $_.IPUseZeroBroadcast;
        IPXAddress                    = $_.IPXAddress;
        IPXEnabled                    = $_.IPXEnabled;
        IPXFrameType                  = $_.IPXFrameType;
        IPXMediaType                  = $_.IPXMediaType;
        IPXNetworkNumber              = $_.IPXNetworkNumber;
        IPXVirtualNetNumber           = $_.IPXVirtualNetNumber;
        KeepAliveInterval             = $_.KeepAliveInterval;
        KeepAliveTime                 = $_.KeepAliveTime;
        MACAddress                    = $_.MACAddress;
        MTU                           = $_.MTU;
        NumForwardPackets             = $_.NumForwardPackets;
        PMTUBHDetectEnabled           = $_.PMTUBHDetectEnabled;
        PMTUDiscoveryEnabled          = $_.PMTUDiscoveryEnabled;
        ServiceName                   = $_.ServiceName;
        SettingID                     = $_.SettingID;
        TcpipNetbiosOptions           = $_.TcpipNetbiosOptions;
        TcpMaxConnectRetransmissions  = $_.TcpMaxConnectRetransmissions;
        TcpMaxDataRetransmissions     = $_.TcpMaxDataRetransmissions;
        TcpNumConnections             = $_.TcpNumConnections;
        TcpUseRFC1122UrgentPointer    = $_.TcpUseRFC1122UrgentPointer;
        TcpWindowSize                 = $_.TcpWindowSize;
    }
});
