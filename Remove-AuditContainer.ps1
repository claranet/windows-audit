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
Write-BuildMessage `
    -Message "Clearing down 'claranet:audit' containers and images" `
    -Stage PreBuild `
    -State Info;

# Make sure the container is gone
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
            -Message "Cleanup failed with exception: $($_.Exception.Message)" `
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
            -Message "Cleanup failed with exception: $($_.Exception.Message)" `
            -Stage DockerBuild `
            -State Failure;
        Exit(1);
    }
}

# And we're done
Write-BuildMessage `
    -Message "Container and image cleanup completed" `
    -Stage PostBuild `
    -State Success;