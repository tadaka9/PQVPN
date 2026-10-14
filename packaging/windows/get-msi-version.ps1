param([Parameter(Mandatory = $true)][string]$Version)
$ErrorActionPreference = 'Stop'
if ($Version -match '^alpha-(\d+)\.(\d+)-\d+-[0-9A-Za-z.-]+$') {
    $parts = @([uint64]$Matches[1], [uint64]$Matches[2], [uint64]0)
} elseif ($Version -match '^(\d+)\.(\d+)-(alpha|beta)-\d+-[0-9A-Za-z.-]+$') {
    $parts = @([uint64]$Matches[1], [uint64]$Matches[2], [uint64]0)
} elseif ($Version -match '^(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?$') {
    $parts = @([uint64]$Matches[1], [uint64]$Matches[2], [uint64]$Matches[3])
} else {
    throw 'Invalid project version label'
}
if ($parts[0] -gt 255 -or $parts[1] -gt 255 -or $parts[2] -gt 65535) {
    throw 'MSI ProductVersion requires major/minor <=255 and patch <=65535'
}
# Windows Installer ignores a fourth component. Each published prerelease
# must use an unused three-component base to preserve major-upgrade ordering.
"$($parts[0]).$($parts[1]).$($parts[2])"
