param([Parameter(Mandatory)][string]$Archive)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Windows.Forms

function Wait-For([scriptblock]$Check, [string]$Description) {
    $until = [DateTime]::UtcNow.AddSeconds(20)
    do {
        $found = & $Check
        if ($found) { return $found }
        Start-Sleep -Milliseconds 100
    } until ([DateTime]::UtcNow -ge $until)
    throw "Timed out: $Description"
}

function Find-Control($Window, [string]$Name, $Type) {
    $nameCondition = [Windows.Automation.PropertyCondition]::new(
        [Windows.Automation.AutomationElement]::NameProperty, $Name)
    $typeCondition = [Windows.Automation.PropertyCondition]::new(
        [Windows.Automation.AutomationElement]::ControlTypeProperty, $Type)
    $condition = [Windows.Automation.AndCondition]::new($nameCondition, $typeCondition)
    Wait-For { $Window.FindFirst([Windows.Automation.TreeScope]::Descendants, $condition) } $Name
}

$scratch = Join-Path ([IO.Path]::GetTempPath()) ('sshash-release-test-' + [guid]::NewGuid())
$package = Join-Path $scratch 'package'
$profile = Join-Path $scratch 'profile'
Expand-Archive -LiteralPath $Archive -DestinationPath $package
New-Item -ItemType Directory -Path $profile | Out-Null
$seed = @{
    hosts = @(@{ id = 'bea87bcf-5e56-4b38-9ef3-2b9a02c52064'; label = 'Release test'; group = 'Lab';
        host = '127.0.0.1'; port = 22; username = 'release-test'; auth = 'password' })
    hostKeys = @{}
} | ConvertTo-Json -Depth 4
[IO.File]::WriteAllText((Join-Path $profile 'servers.json'), $seed)
$exe = Get-ChildItem -LiteralPath $package -Filter SSHnesh.exe -Recurse | Select-Object -First 1
$launch = @{
    FilePath = $exe.FullName
    WorkingDirectory = $scratch
    ArgumentList = ('--force-renderer-accessibility --user-data-dir="' + $profile + '"')
    PassThru = $true
}
$app = Start-Process @launch
try {
    $handle = Wait-For {
        $app.Refresh()
        if ($app.HasExited) { throw "SSHnesh exited with code $($app.ExitCode)." }
        if ($app.MainWindowHandle -ne [IntPtr]::Zero) { $app.MainWindowHandle }
    } 'packaged app window'
    $window = [Windows.Automation.AutomationElement]::FromHandle($handle)
    $button = [Windows.Automation.ControlType]::Button
    try {
        $setup = Find-Control $window 'Настроить Release test' $button
    } catch {
        $names = $window.FindAll([Windows.Automation.TreeScope]::Descendants, [Windows.Automation.Condition]::TrueCondition) |
            ForEach-Object { $_.Current.Name } | Where-Object { $_ }
        Write-Output ($names -join ' | ')
        throw
    }
    $setup.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()
    $shell = New-Object -ComObject WScript.Shell
    if (!$shell.AppActivate($app.Id)) { throw 'Could not bring the release window forward.' }
    (Find-Control $window 'Сохранить и ввести пароль…' $button).SetFocus()
    [Windows.Forms.SendKeys]::SendWait('{ENTER}')
    & "$PSScriptRoot/secret-dialog.ps1" -Mode accept -AppPid $app.Id

    $vault = Join-Path $profile 'workspace.json'
    $path = Wait-For { if (Test-Path -LiteralPath $vault) { $vault } } 'saved password'
    $json = Get-Content -LiteralPath $path -Raw
    $entries = @(($json | ConvertFrom-Json).vault.passwords.PSObject.Properties)
    if ($entries.Count -ne 1 -or !$entries[0].Value.cipher -or $json.Contains('synthetic-secret')) {
        throw 'The release did not save the password as an encrypted record.'
    }
    'PASS extracted Windows release: settings button, automatic keyboard focus, password saved'
} finally {
    if (!$app.HasExited) {
        $null = $app.CloseMainWindow()
        if (!$app.WaitForExit(5000)) { $app.Kill() }
    }
    $absolute = (Resolve-Path -LiteralPath $scratch).Path
    $temp = [IO.Path]::GetTempPath().TrimEnd('\')
    if ([IO.Path]::GetDirectoryName($absolute) -eq $temp -and
        [IO.Path]::GetFileName($absolute) -match '^sshash-release-test-[0-9a-f-]{36}$') {
        Remove-Item -LiteralPath $absolute -Recurse -Force
    }
}
