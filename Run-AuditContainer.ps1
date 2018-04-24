# Easy writer function
Function Write-BuildMessage {
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$Message,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False)]
        [ValidateSet("PreBuild","DotNetBuild","DockerBuild","PostBuild")]
        [String]$Stage,
        [Parameter(Mandatory=$True,ValueFromPipeline=$False)]
        [ValidateSet("Success","Failure","Info")]
        [String]$State
    )

    # Convert our stage indicator
    Switch($Stage) {
        "PreBuild"    {
            $StageDisplayName = "Pre-build Task";
            $StageColour = "Magenta";
        };
        "DotNetBuild" {
            $StageDisplayName = ".NET Build Task";
            $StageColour = "Cyan";
        };
        "DockerBuild" {
            $StageDisplayName = "Docker Build Task";
            $StageColour = "Blue";
        };
        "PostBuild" {
            $StageDisplayName = "Post Build Task";
            $StageColour = "DarkGreen";
        }
    };

    # Decide our state colour
    $StateColour = $(Switch($State){
        "Success" {"Green"};
        "Failure" {"Red"};
        "Info"    {"Yellow"};
    });

    # Get our datestamp
    $DateStamp = Get-Date -f "dd/MM/yy-HH:mm:ss";

    # Start writing to screen
    Write-Host "[$Datestamp] " -ForegroundColor $StateColour -NoNewline;
    Write-Host "[$($State.ToUpper())] " -ForegroundColor $StateColour -NoNewline;
    Write-Host "<$StageDisplayName>" -ForegroundColor $StageColour -NoNewline;
    Write-Host " ~$ $Message" -ForegroundColor $StateColour;
}

# Set EAP
$ErrorActionPreference = "Stop";

# Write out header
$StartTime = Get-Date;
Write-BuildMessage `
    -Message "Building Claranet Audit application and container" `
    -Stage PreBuild `
    -State Info;

# Ok first we want to clear out the build directories of temporary files
Write-BuildMessage `
    -Message "Clearing out temporary development files" `
    -Stage PreBuild `
    -State Info;

try {
    # Enumerate the data directories so they get compiled fresh when the app starts
    "Credentials","Data","Encryption","Hosts","Results" | %{

        Write-BuildMessage `
            -Message "Removing files from '$_'" `
            -Stage PreBuild `
            -State Info;

        # Enumerate the files in the data directory
        Get-ChildItem ".\Code\Audit\$_" -Recurse -Force | %{
            
            Write-BuildMessage `
                -Message "Removing file '$($_.FullName)'" `
                -Stage PreBuild `
                -State Info;

            # And remove the file
            Remove-Item $_.FullName -Force;
        }
    }
} catch {
    Write-BuildMessage `
        -Message "Build failed while removing temporary development files with exception: $($_.Exception.Message)" `
        -Stage PreBuild `
        -State Failure;
    Exit(1);
}


# Next we want to clear out the existing builds
Write-BuildMessage `
    -Message "Clearing out previous build" `
    -Stage PreBuild `
    -State Info;

try {
    # Remove the files
    Remove-Item ".\Code\bin\Release" -Recurse -Force -ErrorAction SilentlyContinue;
    Remove-Item ".\Code\obj\Release" -Recurse -Force -ErrorAction SilentlyContinue;
    Remove-Item ".\Code\obj\netcoreapp2.0" -Recurse -Force -ErrorAction SilentlyContinue;
} catch {
    Write-BuildMessage `
        -Message "Build failed while clearing out previous build with exception: $($_.Exception.Message)" `
        -Stage PreBuild `
        -State Failure;
    Exit(1);
}

# Build/publish the core solution
Write-BuildMessage `
    -Message "Building and publishing Audit application" `
    -Stage DotNetBuild `
    -State Info;

try {
    # Build the publish args for clarity
    $Publish = @(
        "dotnet publish",
        "'.\Code\claranet-audit.csproj'",
        "--configuration 'Release'",
        "--self-contained",
        "--runtime 'win10-x64'",
        "--verbosity n"
    ) -Join " ";
    
    # Invoke the build
    Invoke-Expression $Publish;

    # Write success
    Write-BuildMessage `
        -Message ".NET build completed successfully" `
        -Stage DotNetBuild `
        -State Success;

} catch {
    Write-BuildMessage `
        -Message "Build failed with exception: $($_.Exception.Message)" `
        -Stage DotNetBuild `
        -State Failure;
    Exit(1);
}

# Make sure the container doesn't already exist
if (((Invoke-Expression "docker ps -a") -Join "`r`n") -like "*claranet*audit*") {
    
    Write-BuildMessage `
        -Message "Clearing existing container 'claranet:audit'" `
        -Stage DockerBuild `
        -State Info;

    try {
        # Stop the container
        [Void](Invoke-Expression "docker stop claranet:audit");

        # Remove the container
        [Void](Invoke-Expression "docker rm claranet:audit");

    } catch {
        Write-BuildMessage `
            -Message "Build failed while trying to clear existing container with exception: $($_.Exception.Message)" `
            -Stage DockerBuild `
            -State Failure;
        Exit(1);
    }
}

# Make sure the image doesn't already exist
if (((Invoke-Expression "docker images") -Join "`r`n") -like "*claranet*audit*") {
    
    Write-BuildMessage `
        -Message "Clearing existing container image 'claranet:audit'" `
        -Stage DockerBuild `
        -State Info;

    try {
        # Remove the image
        [Void](Invoke-Expression "docker rmi claranet:audit");

    } catch {
        Write-BuildMessage `
            -Message "Build failed while trying to clear existing image with exception: $($_.Exception.Message)" `
            -Stage DockerBuild `
            -State Failure;
        Exit(1);
    }
}

# Build the new docker image
Write-BuildMessage `
    -Message "Creating new docker image for 'claranet:audit'" `
    -Stage DockerBuild `
    -State Info;

try {
    # Invoke the build
    docker build -t 'claranet:audit' .

    # Check the last result and throw if broken
    if ($LASTEXITCODE -gt 0) {
        throw "(printed to stdout above)";
    }

    # Write success
    Write-BuildMessage `
        -Message "Docker build completed successfully" `
        -Stage DockerBuild `
        -State Success;

} catch {
    Write-BuildMessage `
        -Message "Build failed while trying create docker image with exception: $($_.Exception.Message)" `
        -Stage DockerBuild `
        -State Failure;
    Exit(1);
}

# Create a container from the image we just built
Write-BuildMessage `
    -Message "Building docker container using image 'claranet:audit'" `
    -Stage DockerBuild `
    -State Info;

try {
    # Invoke the run switching to bypass Windows 10 silent memory cap issue
    if ((Get-WmiObject "Win32_OperatingSystem").Caption.Contains("Windows 10")) {
        docker run --memory 8GB --rm --publish 5001:5000 claranet:audit;
    } else {
        docker run --rm --publish 5001:5000 claranet:audit;
    }
    
    # Check the last result and throw if broken
    if ($LASTEXITCODE -gt 0) {
        throw "(printed to stdout above)";
    }

} catch {
    Write-BuildMessage `
        -Message "Build failed while creating docker container with exception: $($_.Exception.Message)" `
        -Stage DockerBuild `
        -State Failure;
    Exit(1);
}

# Start the audit application
Write-BuildMessage `
    -Message "Launching Claranet Audit" `
    -Stage PostBuild `
    -State Success;

try {
    # Invoke the audit application page
    Start-Process "http://localhost:5001";
} catch {
    Write-BuildMessage `
        -Message "Failed to launch application start page with exception: $($_.Exception.Message)" `
        -Stage PostBuild `
        -State Failure;
    Exit(1);
}

# And we're done
$EndTime = Get-Date;
$TS = New-TimeSpan $StartTime $EndTime;

Write-BuildMessage `
    -Message "Build completed successfully in $($TS.ToString().Split(".")[0])" `
    -Stage PostBuild `
    -State Success;

Exit(0);