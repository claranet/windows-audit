[CmdletBinding()]
Param(
    # Guid for matching back to the correc machine
    [Parameter(Mandatory=$True)]
    [ValidateScript({$_ -Match "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"})]
    [String]$ID
)

# Set EAP
$ErrorActionPreference = "Stop";

# Get the certificate tree
$TLSCertificates = $(Get-ChildItem "Cert:\LocalMachine" -Recurse | ?{!$_.PSIsContainer -and $_.Subject -notlike "CN=DSC-*"} | Select -Property * | %{
    New-Object PSCustomObject -Property @{
        MachineIdentifier        = $ID;
        EnhancedKeyUsageList     = $_.EnhancedKeyUsageList;
        DnsNameList              = $_.DnsNameList;
        SendAsTrustedIssuer      = $_.SendAsTrustedIssuer;
        EnrollmentPolicyEndPoint = $_.EnrollmentPolicyEndPoint;
        EnrollmentServerEndPoint = $_.EnrollmentServerEndPoint;
        PolicyId                 = $_.PolicyId;
        Archived                 = $_.Archived;
        Extensions               = $_.Extensions;
        FriendlyName             = $_.FriendlyName;
        IssuerName               = $_.IssuerName;
        NotAfter                 = $_.NotAfter;
        NotBefore                = $_.NotBefore;
        HasPrivateKey            = $_.HasPrivateKey;
        PublicKey                = $_.PublicKey;
        SerialNumber             = $_.SerialNumber;
        SubjectName              = $_.SubjectName;
        SignatureAlgorithm       = $_.SignatureAlgorithm;
        Thumbprint               = $_.Thumbprint;
        Version                  = $_.Version;
        Handle                   = $_.Handle;
        Issuer                   = $_.Issuer;
        Subject                  = $_.Subject;
    }
});

# And return
return ,$TLSCertificates;