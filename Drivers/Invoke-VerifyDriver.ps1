<#
.SYNOPSIS
  Invoke-VerifyDriver.ps1

.DESCRIPTION
  This script checks if the inf and cab has been signed by a Hardware signing certificate. It also extract and displays info from the inf file of each drivers.
  If any data is missing or incorrect it is likly due to the provider has not entered the correct data in the inf file.

.PARAMETER FolderPath
  Path to where the Drivers are.

.PARAMETER ListPNPIds
  Use if you require all supported PNP IDs to be listed, if not specified they will be omitted from the result.


.NOTES
  Version:        1.0
  Author:         Mattias Benninge @ 2Pint Software
  Creation Date:  2023-11-27
  Purpose/Change: Initial script development

.EXAMPLE
    Invoke-VerifyDriver.ps1 -FolderPath C:\Drivers
#>
#---------------------------------------------------------[Script Parameters]------------------------------------------------------
Param (
    [parameter(Mandatory = $true)]
    [string]$FolderPath,
    [Switch]$ListPNPIds
)
#---------------------------------------------------------[Initialisations]--------------------------------------------------------
#Set Error Action to Silently Continue
$ErrorActionPreference = 'SilentlyContinue'
#----------------------------------------------------------[Declarations]----------------------------------------------------------
$DriverObjects = @()
#-----------------------------------------------------------[Functions]------------------------------------------------------------
function Get-IniFile {
    <#
    .SYNOPSIS
    Read an ini file.
    
    .DESCRIPTION
    Reads an ini file into a hash table of sections with keys and values.
    
    .PARAMETER filePath
    The path to the INI file.
    
    .PARAMETER anonymous
    The section name to use for the anonymous section (keys that come before any section declaration).
    
    .PARAMETER comments
    Enables saving of comments to a comment section in the resulting hash table.
    The comments for each section will be stored in a section that has the same name as the section of its origin, but has the comment suffix appended.
    Comments will be keyed with the comment key prefix and a sequence number for the comment. The sequence number is reset for every section.
    
    .PARAMETER commentsSectionsSuffix
    The suffix for comment sections. The default value is an underscore ('_').

    .PARAMETER commentsKeyPrefix
    The prefix for comment keys. The default value is 'Comment'.
    
    .EXAMPLE
    Get-IniFile /path/to/my/inifile.ini
    
    .NOTES
    The resulting hash table has the form [sectionName->sectionContent], where sectionName is a string and sectionContent is a hash table of the form [key->value] where both are strings.
    #>
    
    param(
        [parameter(Mandatory = $true)] [string] $filePath,
        [string] $anonymous = 'NoSection',
        [switch] $comments,
        [string] $commentsSectionsSuffix = '_',
        [string] $commentsKeyPrefix = 'Comment'
    )

    $ini = @{}
    switch -regex -file ($filePath) {
        "^\[(.+)\]" {
            # Section
            $section = $matches[1]
            $ini[$section] = @{}
            $CommentCount = 0
            if ($comments) {
                $commentsSection = $section + $commentsSectionsSuffix
                $ini[$commentsSection] = @{}
            }
            continue
        }

        "^(;.*)$" {
            # Comment
            if ($comments) {
                if (!($section)) {
                    $section = $anonymous
                    $ini[$section] = @{}
                }
                $value = $matches[1]
                $CommentCount = $CommentCount + 1
                $name = $commentsKeyPrefix + $CommentCount
                $commentsSection = $section + $commentsSectionsSuffix
                $ini[$commentsSection][$name] = $value
            }
            continue
        }

        "^(.+?)\s*=\s*(.*)$" {
            # Key
            if (!($section)) {
                $section = $anonymous
                $ini[$section] = @{}
            }
            $name, $value = $matches[1..2]
            #$CurrentValues = $ini[$section].Count
            If ($ini[$section][$name]) {
                $ini[$section][$name] += "|$value"
            }
            else {
                $ini[$section][$name] = $value
            }
            
            continue
        }
        "^$" {
            # ignore blank line
        }
        default {
            if (!($section)) {
                $section = $anonymous
                $ini[$section] = @{}
            }
            $ini[$section]["Text"] = $_
            continue
        }
    }

    return $ini
}


$Csharp = @"
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
public struct INF_SIGNER_INFO
{
    public uint cbSize;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string CatalogFile;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string DigitalSigner;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string DigitalSignerVersion;
}

namespace TwoPint.DriverInfo
{
    public class InfInfo
    {
        [DllImport("setupapi.dll", EntryPoint = "SetupDiClassNameFromGuidW", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool SetupDiClassNameFromGuid(
            ref Guid theGuid, StringBuilder returnBuffer, uint returnBufferSize, out uint requiredSize);
            
        [DllImport("setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool SetupVerifyInfFile(string infName, IntPtr AltPlatformInfo, ref INF_SIGNER_INFO InfSignerInfo);
    }
}
"@

Add-Type -TypeDefinition $Csharp -Language CSharp 

#-----------------------------------------------------------[Execution]------------------------------------------------------------

Write-host "Searching for inf files in folder : $FolderPath"

$drivers = Get-ChildItem -Path $FolderPath -Filter "*.inf" -Recurse

if (!$drivers) { Write-host "No Drivers found in $FolderPath" ; break }
Write-host "Found $($drivers.Count) drivers."
Write-host "Checking drivers, might take a while if there is a lot..."

$DriverObjects = @()
foreach ($inf in $drivers) {
    $SupportedOS = @()
    $SupportedPlatforms = @()
    $IsSigned = $False
    
    $csharpPath = $inf.FullName -replace "\\", "\\"
    $SignerInfo = [INF_SIGNER_INFO]::new()
    $SignerInfo.cbSize = [UInt32][System.Runtime.InteropServices.Marshal]::SizeOf($SignerInfo)
    $signedResult = [TwoPint.DriverInfo.InfInfo]::SetupVerifyInfFile($csharpPath, [System.IntPtr]::Zero, [ref]$SignerInfo )
    if ($signedResult) {
        $IsSigned = $True
    }
    else {
        $IsSigned = $False
    }

    $inifile = Get-IniFile -filePath $inf.FullName

    $infClassGUID = ($inifile.version["ClassGuid"] -split ";")[0].Trim()
    $infProvider = ($inifile.version["Provider"] -split ";")[0].Trim()
    if ($infProvider -match '^%(.+)%$') {
        $infProvider = ($inifile.Strings["$($infProvider.Substring(1,$infProvider.Length-2))"] -replace '"', "" -split ";")[0].Trim()
    }

    if ($IsSigned) {
        $infCatalogFile = $SignerInfo.CatalogFile
    }
    Else {
        $infCatalogFile = ($inifile.version["CatalogFile"] -split ";")[0].Trim()
    }
    
    $infDriverDate = ($inifile.version["DriverVer"] -split ",")[0].Trim()
    $infDriverVer = (($inifile.version["DriverVer"] -split ",", 2)[1] -split ";")[0].Trim()
    $infManufacturer = ($inifile.Manufacturer.Keys[0]).Trim()
    if ($infManufacturer -match '^%(.+)%$') {
        $infManufacturer = ($inifile.Strings["$($infManufacturer.Substring(1,$infManufacturer.Length-2))"] -replace '"', "" -split ";")[0].Trim()
    }

    [Array]$infPlatforms = ((($inifile.Manufacturer.Values[0] -split ";", 2)[0].Trim() -split ",", 2)[1] -split ",").Trim()
    $infManufacturerPlatform = (($inifile.Manufacturer.Values[0] -split ",", 2)[0] -split ";")[0].Trim()

    $StringBuilder = [System.Text.StringBuilder]::New(4096)
    
    $classNameResult = [TwoPint.DriverInfo.InfInfo]::SetupDiClassNameFromGuid([System.Management.Automation.PSReference][guid]$infClassGUID, $StringBuilder, 4096, [System.Management.Automation.PSReference]0)
    if ($classNameResult) {   
        $infClass = $StringBuilder.ToString()
    }
    else {
        $infClass = ($inifile.version["Class"] -split ";")[0].Trim()
    }
    $StringBuilder = $null

    $IniDeviceSection = $null
    [Array]$IniDeviceSection = $inifile.Keys | Where-Object { $_ -like "$($infManufacturerPlatform)*" }

    $PNPIds = @() 
    foreach ($IniDevice in $infPlatforms) {
        IF (($inifile."$infManufacturerPlatform.$IniDevice").Count -ge 1) {
            $IniDeviceArray = $IniDevice -split "\.", 2
            $SupportedOS += $IniDeviceArray[1]

            switch ($IniDeviceArray[0]) {
                "NTamd64" { $SupportedPlatforms += "x64" }
                "NTarm64" { $SupportedPlatforms += "x64" }
                "NTia64" { $SupportedPlatforms += "x64" }
                "NTx86" { $SupportedPlatforms += "x86" }
                Default { 
                    $SupportedPlatforms += "x86" 
                }
            }

            foreach ($PNPId in ($inifile."$infManufacturerPlatform.$IniDevice").Values) {
                $PNPId = (($PNPId -split ";", 2)[0] -split ",", 2)[1].Trim()
                $PNPIds += $PNPId
            }
        }
    }
    
    $SupportedPlatforms = ($SupportedPlatforms | Group-Object).Name 
    if ($SupportedPlatforms -gt 1) { $SupportedPlatforms = $SupportedPlatforms -join "," }
    
    $SupportedOS = ($SupportedOS | Group-Object).Name
    if ($SupportedOS -gt 1) { $SupportedOS = $SupportedOS -join "," }
    
    $PNPIds = ($PNPIds | Group-Object).Name
    if ($PNPIds -gt 1) { $PNPIds = ($PNPIds | Out-String).Trim() }
    else { $PNPIds = ($PNPIds | Out-String).Trim() }
    
    # This Hash should match the one created by the MDT Workbench
    $HashString = (((Get-ChildItem $path -Recurse | Get-FileHash -Algorithm SHA256).Hash -join "").Trim() | Out-String ).Trim()
    $Hash = (Get-FileHash -InputStream ([IO.MemoryStream]::new([char[]]$HashString))).Hash

    $DriverObject = [PSCustomObject]@{
        Name                 = $inf.Name
        Manufacturer         = $infManufacturer
        Provider             = $infProvider
        ClassName            = $infClass
        Date                 = $infDriverDate
        Version              = $infDriverVer
        IsSigned             = $IsSigned
        Platform             = $SupportedPlatforms
        SupportedOS          = $SupportedOS
        CatalogFile          = $infCatalogFile 
        DigitalSigner        = $SignerInfo.DigitalSigner
        DigitalSignerVersion = $SignerInfo.DigitalSignerVersion
        FolderHash           = $Hash
        ClassGUID            = $infClassGUID        
        PNPIds               = ''
    }
    #$DriverObject
    If ($ListPNPIds) {
        $DriverObject.PNPIds = $PNPIds
    }

    $DriverObjects += $DriverObject

    $SignerInfo = $null
    $StringBuilder = $null

}
Write-host "Done!"
$DriverObjects | Out-GridView -Title "2Pint Driver Info by Matt Benninge"