# Dockerfile for Audit container
FROM microsoft/powershell:ubuntu16.04

LABEL maintainer="John George <john.george@claranet.uk>" \
      readme.md="https://github.com/claranet/windows-audit/README.md" \
      description="This dockerfile will build a container to host Audit scripting."

# Setup the locale
RUN locale-gen en_GB.UTF-8
ENV LANG='en_GB.UTF-8' LANGUAGE='en_GB:en' LC_ALL='en_GB.UTF-8'

# Install Nmap
RUN apt-get install -y --no-install-recommends nmap

# Copy local project files across
COPY . /etc/windows-audit

# Use PowerShell as the default shell starting in the audit directory
CMD [ "pwsh", \
      "-noexit", \
      "-command", \
      "Write-Host '# Audit Container POC' -ForegroundColor Yellow;Write-Host '# For more information and help please visit: https://github.com/claranet/windows-audit' -ForegroundColor Yellow;cd /etc/windows-audit " \
]
