<#
    .SYNOPSIS
    Name: Parse-WindowsAuditData.ps1
    Parses the results from Get-WindowsAuditData.ps1
    
    .DESCRIPTION
    This script is a thin wrapper to provide ease of use for the filters in
    this solution. The filters provide a way to parse the same data repeatedly
    to create different views of the data, this will validate that the filter
    chosen is valid and call the filter multiple times providing each file from
    the RawData directory.

    .EXAMPLE
    .\Parse-WindowsAuditData.ps1 -Filter Example
    This will parse the entire contents of the RawData directory, generating
    the output CSV files for compliation using the 'Example' filter.

    .TODO# Need to add error handling and output logging

    #requires -version 5
#>

# Dynamic parameter so we can autocomplete the filters
DynamicParam {       
    # Create the attribute collection
    $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute];
    
    # Create and set the attributes
    $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute;
    $ParameterAttribute.Mandatory = $False;

    # Add the attributes to the attributes collection
    $AttributeCollection.Add($ParameterAttribute);
        
    # Create the dictionary 
    $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary;
                
    # Generate and set the ValidateSet 
    $ArraySet = (Get-ChildItem -Path "..\Filters" -File | Select-Object -ExpandProperty Name).Replace(".ps1","");
    $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($ArraySet);

    # Add the ValidateSet to the attributes collection
    $AttributeCollection.Add($ValidateSetAttribute);
        
    # Create and add the dynamic param to the dict
    $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter("Filter", [string], $AttributeCollection);
    $RuntimeParameterDictionary.Add("Filter", $RuntimeParameter);
}

Process {
    # Get the filter name from the dynamic parameter
    $FilterName = $PSBoundParameters["Filter"];
    $FilterPath = ".\Filters\$FilterName.ps1";

    # Get a list of the CLI XML files to process
    $CliXmlFilesToProcess = Get-ChildItem ".\RawData\*cli.xml";

    # Enumerate the collection
    $CliXmlFilesToProcess | %{
        # Get the CLI XML back into a PSCustomObject
        $HostInformation = Import-Clixml -Path $_.FullName;

        # And pass the result on to the correct filter for execution
        & $FilterPath -HostInformation $HostInformation;
    }
}