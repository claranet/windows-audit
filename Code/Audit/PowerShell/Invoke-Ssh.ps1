[Cmdletbinding()]
Param(
    # The server we're targetting
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String]$Target,

    # Username we'll use to connect
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String]$Username,

    # Password we'll use to connect
    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String]$Password,

    # Private key file path 
    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String]$PrivateKeyFilePath,

    # Passphrase for the private key
    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String]$PrivateKeyPassphrase,

    # The script we're executing
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String]$ScriptPath,

    # The Machine identifer we'll tag the result with
    [Parameter(Mandatory=$True)]
    [ValidateScript({$_ -Match "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"})]
    [String]$MachineIdentifier
)

# Set EAP
$ErrorActionPreference = "Stop";

# Work out the authentication mechansim
$AuthenticationMethod = $(
    if ($Username -and $PrivateKeyFilePath -and $PrivateKeyPassphrase) {
        "PrivateKeyWithPassphrase";
    } elseif ($Username -and $PrivateKeyFilePath) {
        "PrivateKey";
    } else {
        "Password";
    }
);

# Switch on the auth method
Switch($AuthenticationMethod) {
    "Password" {
        $Result = Invoke-Expression $("plink -ssh $Target -P 22 -l $Username -pw $Password -batch -m $ScriptPath") | ConvertFrom-Json;
    }
    "PrivateKey" {
        $Result = Invoke-Expression $("plink -ssh $Target -P 22 -l $Username -i $PrivateKeyFilePath -batch -m $ScriptPath") | ConvertFrom-Json;
    }
    "PrivateKeyWithPassphrase" {
        # Wrap the ssh connection in a Process so we can write to stdin
        $ProcessStartInfo = New-Object System.Diagnostics.ProcessStartInfo;
        $Process = New-Object System.Diagnostics.Process;

        # Set the startinfo object properties and set the process to use this startinfo
        $ProcessStartInfo.FileName = $($env:windir + "\System32\cmd.exe");
        $ProcessStartInfo.CreateNoWindow = $True;
        $ProcessStartInfo.UseShellExecute = $False;
        $ProcessStartInfo.RedirectStandardOutput = $True;
        $ProcessStartInfo.RedirectStandardInput = $True;
        $ProcessStartInfo.RedirectStandardError = $True;
        $Process.StartInfo = $ProcessStartInfo;

        # Start the process
        [Void]($Process.Start());

        # Cmd and execute
        $Cmd = "plink -ssh $Target -P 22 -l $Username -i $PrivateKeyFilePath -m $ScriptPath";
        $Process.StandardInput.Write($Cmd + [System.Environment]::NewLine);
            
        # Wait for 2 seconds and write the private key passphrase to stdin
        Start-Sleep -Seconds 2;
        $Process.StandardInput.Write($PrivateKeyPassphrase + [System.Environment]::NewLine);

        # Close stdin now we're done with it
        $Process.StandardInput.Close();

        # Block the exit until completion
        $Process.WaitForExit();

        # Grab stderr, stdout and exit code in case we need to throw
        $Stderr = $Process.StandardError.ReadToEnd();
        $Stdout = $Process.StandardOutput.ReadToEnd();
        $Status = $Process.ExitCode;

        # Check our results first
        if (![String]::IsNullOrEmpty($Stderr) -or $Status -gt 0) {
            throw $Stderr;
        }

        # Process the result
        $StartIndex = $Stdout.IndexOf("{");
        $EndIndex = $Stdout.LastIndexOf("}") - $StartIndex + 1;
        $Result = $Stdout.Substring($StartIndex,$EndIndex) | ConvertFrom-Json;       
    }
}

# Add the machine identifier
$Result.MachineIdentifier = $MachineIdentifier;

# And return
return $Result;