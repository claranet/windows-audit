# Build test script using vagrant 2008 R2 box

# Make sure the vagrant box is up
Write-Host "Running command 'vagrant up' on 'windows-audit' solution" -ForegroundColor Yellow;
Invoke-Expression "vagrant up";

# Get our PSCredential in scope
Write-Host "Building credentials" -ForegroundColor Yellow;
$Password = "vagrant" | ConvertTo-SecureString -AsPlainText -Force;
$PSCredential = New-Object System.Management.Automation.PSCredential("vagrant",$Password);

# Execute our script against the vagrant box
Write-Host "Invoking test" -ForegroundColor Yellow;
$HostInfo = .\Invoke-WindowsAudit.ps1 -Computers "127.0.0.1:55985" -PSCredential $PSCredential;

Write-Host "Get host information for: $($HostInfo.HostName)" -ForegroundColor Magenta;
$HostInfo.HostInfo;