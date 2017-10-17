# Build test script using vagrant 2008 R2 box

# Make sure the vagrant box is up
Invoke-Expression "vagrant up";

# Get our PSCredential in scope
$Password = "vagrant" | ConvertTo-SecureString -AsPlainText -Force;
$PSCredential = New-Object System.Management.Automation.PSCredential("vagrant",$Password);

# Execute our script against the vagrant box
.\Invoke-WindowsAudit.ps1 -Computers "127.0.0.1:55985" -PSCredential $PSCredential;