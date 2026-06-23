[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("configure", "compile", "build", "rebuild", "clean")]
    [string] $Command,

    [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
    [string[]] $CmakeJsArgs = @(),

    [Parameter()]
    [string] $Arch = "x64",

    [Parameter()]
    [string] $HostArch = "x64",

    [Parameter()]
    [string] $WindowsSdkVersion = "10.0.22621.0",

    [Parameter()]
    [string] $MsvcVersion = "14.38"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Resolve-VsWhere {
    $programFilesX86 = [Environment]::GetFolderPath("ProgramFilesX86")
    $candidate = Join-Path $programFilesX86 "Microsoft Visual Studio\Installer\vswhere.exe"

    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
        return $candidate
    }

    $command = Get-Command "vswhere.exe" -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }

    throw "Unable to find vswhere.exe. Install Visual Studio Installer or add vswhere.exe to PATH."
}

function Resolve-VisualStudioInstallation {
    $vswhere = Resolve-VsWhere
    $installations = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -format json | ConvertFrom-Json

    if ($LASTEXITCODE -ne 0 -or $null -eq $installations) {
        throw "Unable to find a Visual Studio installation with MSVC C++ tools."
    }

    return $installations | Select-Object -First 1
}

function Import-VisualStudioDevShell {
    param(
        [Parameter(Mandatory = $true)]
        [string] $VsInstallPath
    )

    $modulePath = Join-Path $VsInstallPath "Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
    $legacyModulePath = Join-Path $VsInstallPath "Common7\Tools\vsdevshell\Microsoft.VisualStudio.DevShell.dll"

    if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
        $modulePath = $legacyModulePath
    }

    if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
        throw "Microsoft.VisualStudio.DevShell.dll was not found under $VsInstallPath. Repair the Visual Studio installation."
    }

    Import-Module $modulePath
}

function Assert-RequiredToolchain {
    param(
        [Parameter(Mandatory = $true)]
        [string] $VsInstallPath
    )

    $msvcRoot = Join-Path $VsInstallPath "VC\Tools\MSVC"
    if (-not (Test-Path -LiteralPath $msvcRoot -PathType Container)) {
        throw "Visual Studio MSVC tools directory was not found: $msvcRoot"
    }

    $msvcToolset = Get-ChildItem -LiteralPath $msvcRoot -Directory |
    Where-Object { $_.Name -eq $MsvcVersion -or $_.Name.StartsWith("$MsvcVersion.") } |
    Sort-Object -Property Name -Descending |
    Select-Object -First 1

    if ($null -eq $msvcToolset) {
        throw "Required MSVC toolset $MsvcVersion was not found under $msvcRoot. Install MSVC v143 $MsvcVersion build tools."
    }

    $sdkIncludePath = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\Include\$WindowsSdkVersion"
    if (-not (Test-Path -LiteralPath $sdkIncludePath -PathType Container)) {
        throw "Required Windows SDK $WindowsSdkVersion was not found at $sdkIncludePath. Install this exact Windows SDK version."
    }

    return $msvcToolset.Name
}

if ([string]::IsNullOrWhiteSpace($Command)) {
    throw "Usage: scripts/cmake-js-msvc.ps1 <configure|compile|build|rebuild|clean> [cmake-js arguments...]"
}

$visualStudio = Resolve-VisualStudioInstallation
$vsInstallPath = $visualStudio.installationPath
$vsInstanceId = $visualStudio.instanceId
$launchVsDevShell = Join-Path $vsInstallPath "Common7\Tools\Launch-VsDevShell.ps1"

if (-not (Test-Path -LiteralPath $launchVsDevShell -PathType Leaf)) {
    throw "Launch-VsDevShell.ps1 was not found at $launchVsDevShell"
}

$resolvedMsvcVersion = Assert-RequiredToolchain -VsInstallPath $vsInstallPath

$devCmdArguments = "-vcvars_ver=$MsvcVersion -winsdk=$WindowsSdkVersion"
Import-VisualStudioDevShell -VsInstallPath $vsInstallPath
Enter-VsDevShell -VsInstanceId $vsInstanceId -Arch $Arch -HostArch $HostArch -SkipAutomaticLocation -DevCmdArguments $devCmdArguments

if ($LASTEXITCODE -ne 0) {
    throw "Enter-VsDevShell failed with exit code $LASTEXITCODE."
}

$env:VCToolsVersion = $resolvedMsvcVersion
$env:WindowsSDKVersion = "$WindowsSdkVersion\"

$cmakeJsBin = Join-Path $PSScriptRoot "..\node_modules\.bin\cmake-js.cmd"
if (-not (Test-Path -LiteralPath $cmakeJsBin -PathType Leaf)) {
    throw "cmake-js was not found at $cmakeJsBin. Install project dependencies before building."
}

& $cmakeJsBin $Command @CmakeJsArgs
exit $LASTEXITCODE