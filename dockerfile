# Dockerfile for Audit container
FROM microsoft/windowsservercore:10.0.14393.2189

LABEL maintainer="John George <john.george@claranet.uk>" \
      readme.md="https://github.com/claranet/windows-audit/README.md" \
      description="This dockerfile will build a container to host Audit scripting."

# Configure the container os
RUN powershell -NoProfile -ExecutionPolicy Bypass -Command " \
      Set-WinSystemLocale 'en-GB'; \
      Set-TimeZone 'GMT Standard Time'; \
      Invoke-Expression $(curl https://chocolatey.org/install.ps1 -UseBasicParsing | Select -ExpandProperty Content); \
      choco install -y git -params '\"/GitAndUnixToolsOnPath\"'; \
      choco install -y poshgit; \
      choco install -y putty; \
"

# Copy local project files across
COPY . C:/windows-audit

# Use PowerShell as the default shell starting in the audit directory
CMD "powershell \
-ExecutionPolicy Bypass \
-NoExit \
-Command \
Write-Host '# Claranet Audit Container' -ForegroundColor Yellow; \
Write-Host '# For more information and help please visit: https://github.com/claranet/windows-audit' -ForegroundColor Yellow; \
cd C:\windows-audit \
"