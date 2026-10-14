param(
    [Parameter(Mandatory = $true)][string]$Artifacts,
    [Parameter(Mandatory = $true)][string]$Version
)
$ErrorActionPreference = 'Stop'
$zip = @(Get-ChildItem $Artifacts -Filter '*.zip')
$msi = @(Get-ChildItem $Artifacts -Filter '*.msi')
if ($zip.Count -ne 1 -or $msi.Count -ne 1) { throw 'Expected one ZIP and one MSI' }
$root = Join-Path $env:RUNNER_TEMP 'pqvpn-package-tests'
New-Item -ItemType Directory -Force -Path $root | Out-Null
$portable = Join-Path $root 'portable'
Expand-Archive $zip[0].FullName $portable -Force
if (Get-ChildItem $portable -Recurse -Filter '*.sys') { throw 'Unsigned driver must not be packaged' }

function Test-Payload([string]$Bin, [string]$Config, [string]$Phase) {
    $node = Join-Path $Bin 'pqvpn_node.exe'
    Push-Location $Bin
    try {
    if ((& $node --version) -ne "PQVPN $Version" -or $LASTEXITCODE -ne 0) { throw 'Wrong packaged CLI version' }
    & $node --validate-config --config $Config
    if ($LASTEXITCODE -ne 0) { throw 'Packaged configuration validation failed' }
    & (Join-Path $Bin 'pqvpn_tui.exe') --smoke-test --config $Config
    if ($LASTEXITCODE -ne 0) { throw 'Packaged TUI failed' }
    $guiOutput = (& (Join-Path $Bin 'pqvpn_monitor.exe') --smoke-test --verify-installation --node $node --config $Config 2>&1 | Out-String).Trim()
    $guiExit = $LASTEXITCODE
    if ($guiExit -ne 0) { throw "Packaged GUI failed during $Phase with exit code ${guiExit}: $guiOutput" }
    & (Join-Path $Bin 'pqvpn_tui.exe') --smoke-test
    if ($LASTEXITCODE -ne 0) { throw 'Installed TUI default profile failed' }
    } finally { Pop-Location }
}

function Product-Code([string]$Path) {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.OpenDatabase($Path, 0)
    $view = $database.OpenView("SELECT Value FROM Property WHERE Property='ProductCode'")
    $view.Execute()
    $record = $view.Fetch()
    $code = $record.StringData(1)
    foreach ($object in @($record, $view, $database, $installer)) {
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($object)
    }
    return $code
}

function Invoke-Msi([string[]]$Arguments, [string]$LogName) {
    $log = Join-Path $root $LogName
    $process = Start-Process "$env:SystemRoot\System32\msiexec.exe" -ArgumentList (
        $Arguments + @('/qn', '/norestart', 'REBOOT=ReallySuppress', '/l*v', "`"$log`"")
    ) -Wait -PassThru
    if ($process.ExitCode -notin @(0, 3010)) { throw "MSI failed: $($process.ExitCode); see $log" }
}

$oldPath = $env:PATH
$oldPluginPath = $env:QT_PLUGIN_PATH
$oldPlatform = $env:QT_QPA_PLATFORM
$env:PATH = ($env:PATH -split ';' | Where-Object { -not ($env:QT_ROOT_DIR -and $_.StartsWith($env:QT_ROOT_DIR, [StringComparison]::OrdinalIgnoreCase)) }) -join ';'
$env:QT_PLUGIN_PATH = $null
$env:QT_QPA_PLATFORM = 'offscreen'
$codes = @()
try {
    Test-Payload $portable (Join-Path $portable 'config.json') 'portable verification'
    $install = Join-Path $root 'installed'
    $currentCode = Product-Code $msi[0].FullName
    $codes += $currentCode
    # Exercise an actual clean install, not just file extraction.
    Invoke-Msi @('/i', "`"$($msi[0].FullName)`"", "INSTALLDIR=`"$install`"") 'clean-install.log'
    Test-Payload (Join-Path $install 'bin') (Join-Path $install 'share\pqvpn\examples\config.json') 'clean MSI install'
    if (Get-ChildItem $install -Recurse -Filter '*.sys') { throw 'Installer unexpectedly ships a driver' }
    Invoke-Msi @('/x', $currentCode) 'clean-remove.log'
    if (Test-Path (Join-Path $install 'bin\pqvpn_node.exe')) { throw 'Clean removal left the node installed' }

    # Upgrade from the existing immutable repository prerelease, after verifying
    # the published SHA-256 list. Never download/install unchecked fixture bytes.
    $oldTag = 'v0.0.5-alpha-10092026-David0'
    $oldName = 'PQVPN-0.0.5-alpha-10092026-David0-windows-x64.msi'
    $base = "https://github.com/tadaka9/PQVPN/releases/download/$oldTag"
    $sums = Join-Path $root 'SHA256SUMS'
    $oldMsi = Join-Path $root $oldName
    Invoke-WebRequest "$base/SHA256SUMS" -OutFile $sums
    Invoke-WebRequest "$base/$oldName" -OutFile $oldMsi
    $expected = @(Get-Content $sums | Where-Object { $_ -match ('\s+\*?' + [regex]::Escape($oldName) + '$') })
    if ($expected.Count -ne 1) { throw 'Missing unique checksum for upgrade fixture' }
    $hash = ($expected[0] -split '\s+')[0]
    if ($hash -notmatch '^[0-9a-fA-F]{64}$' -or (Get-FileHash $oldMsi -Algorithm SHA256).Hash -ne $hash) { throw 'Upgrade fixture checksum mismatch' }
    $oldCode = Product-Code $oldMsi
    $codes += $oldCode
    Invoke-Msi @('/i', "`"$oldMsi`"", "INSTALLDIR=`"$install`"") 'old-install.log'
    Invoke-Msi @('/i', "`"$($msi[0].FullName)`"", "INSTALLDIR=`"$install`"") 'upgrade.log'
    Test-Payload (Join-Path $install 'bin') (Join-Path $install 'share\pqvpn\examples\config.json') 'MSI upgrade'
    $installer = New-Object -ComObject WindowsInstaller.Installer
    if ($installer.ProductState($oldCode) -eq 5) { throw 'Upgrade left the old product installed' }
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
    Invoke-Msi @('/x', $currentCode) 'upgrade-remove.log'
    if (Test-Path (Join-Path $install 'bin\pqvpn_node.exe')) { throw 'Upgrade removal left the node installed' }
 } catch {
    # Publish the concrete failure in check annotations when log storage is unavailable.
    $message = $_.Exception.Message.Replace('%', '%25').Replace("`r", '%0D').Replace("`n", '%0A')
    Write-Host "::error::Windows package lifecycle: $message"
    foreach ($log in Get-ChildItem $root -Filter '*.log' -ErrorAction SilentlyContinue) {
        $lines = @(Get-Content $log.FullName)
        for ($index = 0; $index -lt $lines.Count; $index++) {
            if ($lines[$index] -match 'Return value 3') {
                $first = [Math]::Max(0, $index - 15)
                $context = ($lines[$first..$index] -join ' ').Replace('%', '%25')
                Write-Host "::error::MSI $($log.Name): $context"
                break
            }
        }
    }
    throw
} finally {
    # Cleanup only product IDs installed by this test, including partial failures.
    foreach ($code in ($codes | Select-Object -Unique)) {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $state = $installer.ProductState($code)
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
        if ($state -eq 5) { Invoke-Msi @('/x', $code) 'cleanup.log' }
    }
    $env:PATH = $oldPath
    $env:QT_PLUGIN_PATH = $oldPluginPath
    $env:QT_QPA_PLATFORM = $oldPlatform
}
Write-Host 'Portable ZIP smoke and MSI clean install/upgrade/remove passed.'
