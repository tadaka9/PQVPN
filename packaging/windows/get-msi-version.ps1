param([Parameter(Mandatory = $true)][string]$Version)
$ErrorActionPreference = 'Stop'
if ($Version -notmatch '^(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?$') {
    throw 'Expected a semantic project version'
}
$parts = @([uint64]$Matches[1], [uint64]$Matches[2], [uint64]$Matches[3])
if ($parts[0] -gt 255 -or $parts[1] -gt 255 -or $parts[2] -gt 65535) {
    throw 'MSI ProductVersion requires major/minor <=255 and patch <=65535'
}
# Windows Installer ignores a fourth component. Each published prerelease
# must use an unused three-component base to preserve major-upgrade ordering.
"$($parts[0]).$($parts[1]).$($parts[2])"
