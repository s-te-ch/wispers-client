# install.ps1 — installer for wcadm and wconnect on Windows.
#
# Usage:
#   irm https://raw.githubusercontent.com/s-te-ch/wispers-client/main/scripts/install.ps1 | iex
#
# Environment variables:
#   $env:VERSION     — release tag to install (default: latest, e.g. v0.8.1)
#   $env:INSTALL_DIR — install directory (default: $env:USERPROFILE\.local\bin)
#   $env:BINS        — comma-separated binaries (default: "wcadm,wconnect")

$ErrorActionPreference = 'Stop'

$Repo = 's-te-ch/wispers-client'
$InstallDir = if ($env:INSTALL_DIR) { $env:INSTALL_DIR } else { "$env:USERPROFILE\.local\bin" }
$Bins = if ($env:BINS) { $env:BINS -split ',' } else { @('wcadm', 'wconnect') }
$Version = $env:VERSION

# Resolve target. At the time of writing, we only ship x86_64 Windows binaries.
$Arch = $env:PROCESSOR_ARCHITECTURE
if ($Arch -ne 'AMD64') {
    Write-Error "Unsupported Windows arch: $Arch (only x86_64 / AMD64 is supported)"
    exit 1
}
$Target = 'x86_64-pc-windows-msvc'

# Resolve version via the /releases/latest redirect.
if (-not $Version) {
    $resp = Invoke-WebRequest `
        -Uri "https://github.com/$Repo/releases/latest" `
        -MaximumRedirection 0 `
        -SkipHttpErrorCheck
    if ($resp.StatusCode -in 301, 302) {
        $Version = ($resp.Headers['Location'] -split '/')[-1]
    } else {
        Write-Error "Could not resolve latest release tag (status $($resp.StatusCode))"
        exit 1
    }
}

# Strip leading 'v' for the archive filename (matches build-cli-binaries.yml).
$VersionNoV = $Version -replace '^v', ''

Write-Host "Installing wispers-client CLI tools"
Write-Host "  target:      $Target"
Write-Host "  version:     $Version"
Write-Host "  install dir: $InstallDir"
Write-Host ""

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$TmpDir = New-Item -ItemType Directory -Force `
    -Path "$env:TEMP\wispers-install-$([Guid]::NewGuid().ToString('N'))"

try {
    foreach ($Bin in $Bins) {
        $Archive = "${Bin}-${VersionNoV}-${Target}.zip"
        $Url = "https://github.com/$Repo/releases/download/$Version/$Archive"
        Write-Host "  downloading $Archive"
        Invoke-WebRequest -Uri $Url -OutFile "$TmpDir\$Archive"
        Expand-Archive -Path "$TmpDir\$Archive" -DestinationPath $TmpDir -Force
        Move-Item -Force -Path "$TmpDir\$Bin.exe" -Destination "$InstallDir\$Bin.exe"
        Write-Host "  installed   $InstallDir\$Bin.exe"
    }
} finally {
    Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
}

# PATH guidance — don't modify the user's environment automatically.
$UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($UserPath -notlike "*$InstallDir*") {
    Write-Host ""
    Write-Host "Done — but $InstallDir is not on your user PATH."
    Write-Host "Add it permanently with:"
    Write-Host ""
    Write-Host "    [Environment]::SetEnvironmentVariable('Path', `"$UserPath;$InstallDir`", 'User')"
    Write-Host ""
    Write-Host "Then open a new terminal."
} else {
    $firstBin = $Bins[0]
    Write-Host ""
    Write-Host "Done. Try: $firstBin --help"
}
