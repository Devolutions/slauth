#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Builds the native slauth libraries and packs the Devolutions.Slauth NuGet package.

.DESCRIPTION
    Cross-compiles the cdylib for each requested Rust target, stages the result into the wrapper's
    runtimes/<rid>/native folder so the .NET host can resolve DllImport("slauth"), then packs.

    Adding a platform means adding one entry to $RidByTarget and passing the target; nothing else in
    the wrapper or the csproj needs to change.

.PARAMETER Targets
    Rust target triples to build. Defaults to the two Windows targets the Desktop Extension ships.

.PARAMETER Version
    Package version. Defaults to the crate version read from Cargo.toml.

.PARAMETER SkipTests
    Skip the managed test run. The tests exercise the real C ABI, so leave them on where possible.
#>
[CmdletBinding()]
param(
    [string[]] $Targets = @('x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc'),
    [string] $Version,
    [string] $Configuration = 'Release',
    [string] $OutputPath = './package',
    [switch] $SkipTests
)

$ErrorActionPreference = 'Stop'

$RidByTarget = @{
    'x86_64-pc-windows-msvc'    = @{ Rid = 'win-x64';     File = 'slauth.dll' }
    'aarch64-pc-windows-msvc'   = @{ Rid = 'win-arm64';   File = 'slauth.dll' }
    'i686-pc-windows-msvc'      = @{ Rid = 'win-x86';     File = 'slauth.dll' }
    'x86_64-unknown-linux-gnu'  = @{ Rid = 'linux-x64';   File = 'libslauth.so' }
    'aarch64-unknown-linux-gnu' = @{ Rid = 'linux-arm64'; File = 'libslauth.so' }
    'x86_64-apple-darwin'       = @{ Rid = 'osx-x64';     File = 'libslauth.dylib' }
    'aarch64-apple-darwin'      = @{ Rid = 'osx-arm64';   File = 'libslauth.dylib' }
}

$WrapperDir = $PSScriptRoot
$RepoRoot = Resolve-Path (Join-Path $WrapperDir '../..')
$ProjectDir = Join-Path $WrapperDir 'Devolutions.Slauth'
$RuntimesDir = Join-Path $ProjectDir 'runtimes'

if (-not $Version) {
    $cargoToml = Get-Content (Join-Path $RepoRoot 'Cargo.toml')
    # Take the first version key, which belongs to [package]; dependency versions come later.
    $Version = ($cargoToml | Select-String -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1).Matches.Groups[1].Value
    if (-not $Version) {
        throw 'Could not read the crate version from Cargo.toml. Pass -Version explicitly.'
    }
}

Write-Host "Packing Devolutions.Slauth $Version" -ForegroundColor Cyan

# Start from a clean runtimes tree so a removed target can't leave a stale native behind in the package.
if (Test-Path $RuntimesDir) {
    Remove-Item $RuntimesDir -Recurse -Force
}

foreach ($target in $Targets) {
    if (-not $RidByTarget.ContainsKey($target)) {
        throw "Unknown Rust target '$target'. Add it to `$RidByTarget in this script."
    }

    $mapping = $RidByTarget[$target]

    Write-Host "==> $target ($($mapping.Rid))" -ForegroundColor Yellow

    Push-Location $RepoRoot
    try {
        & rustup target add $target
        if ($LASTEXITCODE -ne 0) { throw "rustup target add $target failed." }

        & cargo build --release --target $target
        if ($LASTEXITCODE -ne 0) { throw "cargo build for $target failed." }
    }
    finally {
        Pop-Location
    }

    $built = Join-Path $RepoRoot "target/$target/release/$($mapping.File)"
    if (-not (Test-Path $built)) {
        throw "Expected native library not found: $built"
    }

    $destination = Join-Path $RuntimesDir "$($mapping.Rid)/native"
    New-Item $destination -ItemType Directory -Force | Out-Null
    Copy-Item $built (Join-Path $destination $mapping.File) -Force
}

if (-not $SkipTests) {
    # The test project loads the host-architecture cdylib from target/release, so make sure it exists.
    Push-Location $RepoRoot
    try {
        & cargo build --release
        if ($LASTEXITCODE -ne 0) { throw 'cargo build (host) failed.' }
    }
    finally {
        Pop-Location
    }

    Write-Host '==> Running managed tests' -ForegroundColor Yellow
    & dotnet test (Join-Path $WrapperDir 'Devolutions.Slauth.Tests/Devolutions.Slauth.Tests.csproj') --configuration $Configuration
    if ($LASTEXITCODE -ne 0) { throw 'Managed tests failed.' }
}

Write-Host '==> Packing' -ForegroundColor Yellow
& dotnet pack (Join-Path $ProjectDir 'Devolutions.Slauth.csproj') `
    --configuration $Configuration `
    --output $OutputPath `
    -p:Version=$Version
if ($LASTEXITCODE -ne 0) { throw 'dotnet pack failed.' }

Write-Host "Done. Packages in $OutputPath" -ForegroundColor Green
