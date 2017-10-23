# Build test script using vagrant 2008 R2 box

# Make sure the vagrant box is up
Write-Host "Running command 'vagrant up' on 'windows-audit' solution" -ForegroundColor Yellow;
#Invoke-Expression "vagrant up";

# Get our PSCredential in scope
Write-Host "Building credentials" -ForegroundColor Yellow;
$Password = "vagrant" | ConvertTo-SecureString -AsPlainText -Force;
$PSCredential = New-Object System.Management.Automation.PSCredential("AUDITTEST\vagrant",$Password);

# Execute our script against the vagrant box
Write-Host "Invoking test" -ForegroundColor Yellow;
.\Scripts\Get-WindowsAuditData.ps1 -Computers "127.0.0.1:55985" -PSCredential $PSCredential;
Write-Host "Test finished and written to disk" -ForegroundColor Yellow;

# Generate the excel sheets using the example filter
Write-Host "Compiling result data" -ForegroundColor Yellow;
.\Scripts\Compile-WindowsAuditData.ps1 -Filter "example";
Write-Host "Result data compiled" -ForegroundColor Yellow;