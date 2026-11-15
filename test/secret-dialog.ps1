param([string]$Mode = 'cancel', [int]$AppPid = 0)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
Add-Type @'
using System;
using System.Runtime.InteropServices;

public static class SecretTestWindows
{
    delegate bool Visitor(IntPtr handle, IntPtr unused);
    [DllImport("user32.dll")] static extern bool EnumWindows(Visitor visitor, IntPtr unused);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr handle);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr handle, out uint processId);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();

    public static IntPtr Find(uint pid)
    {
        IntPtr found = IntPtr.Zero;
        EnumWindows((handle, _) => {
            uint processId;
            GetWindowThreadProcessId(handle, out processId);
            if (processId != pid || !IsWindowVisible(handle)) return true;
            found = handle;
            return false;
        }, IntPtr.Zero);
        return found;
    }
}
'@
if ($AppPid) {
    $until = [DateTime]::UtcNow.AddSeconds(15)
    do {
        $child = Get-CimInstance Win32_Process -Filter "ParentProcessId = $AppPid AND Name = 'sshash-pipe.exe'" |
            Where-Object { $_.CommandLine -match '--secret' } | Select-Object -First 1
        if (!$child) { Start-Sleep -Milliseconds 100 }
    } until ($child -or [DateTime]::UtcNow -ge $until)
    if (!$child) { throw 'Application did not launch the password dialog.' }
    $proc = [Diagnostics.Process]::GetProcessById($child.ProcessId)
} else {
    $exe = (Resolve-Path -LiteralPath "$PSScriptRoot/../build/bridge/sshash-pipe.exe").Path
    $start = [Diagnostics.ProcessStartInfo]::new($exe, '--secret SSHnesh-test 0')
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $proc = [Diagnostics.Process]::Start($start)
}
try {
    $condition = [Windows.Automation.PropertyCondition]::new(
        [Windows.Automation.AutomationElement]::IsPasswordProperty, $true)
    $until = [DateTime]::UtcNow.AddSeconds(15)
    do {
        Start-Sleep -Milliseconds 100
        if ($proc.HasExited) { throw "Credential dialog exited: $($proc.ExitCode)" }
        $handle = [SecretTestWindows]::Find($proc.Id)
        if ($handle -ne [IntPtr]::Zero) {
            $dialog = [Windows.Automation.AutomationElement]::FromHandle($handle)
            $inputField = $dialog.FindFirst([Windows.Automation.TreeScope]::Descendants, $condition)
        }
    } until ($inputField -or [DateTime]::UtcNow -ge $until)
    if (!$inputField) { throw 'Visible dialog with a masked password field did not open.' }
    if ($Mode -eq 'accept') {
        if ($AppPid) {
            Add-Type -AssemblyName System.Windows.Forms
            $until = [DateTime]::UtcNow.AddSeconds(3)
            while ([SecretTestWindows]::GetForegroundWindow() -ne $handle -and [DateTime]::UtcNow -lt $until) {
                Start-Sleep -Milliseconds 50
            }
            if ([SecretTestWindows]::GetForegroundWindow() -ne $handle) { throw 'The password dialog did not come to the foreground.' }
            [Windows.Forms.SendKeys]::SendWait('synthetic-secret')
        } else {
            $inputField.GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern).SetValue('synthetic-secret')
        }
        $name = -join (0x41f, 0x440, 0x438, 0x43d, 0x44f, 0x442, 0x44c | ForEach-Object { [char]$_ })
        $find = [Windows.Automation.PropertyCondition]::new([Windows.Automation.AutomationElement]::NameProperty, $name)
        $accept = $dialog.FindFirst([Windows.Automation.TreeScope]::Descendants, $find)
        $until = [DateTime]::UtcNow.AddSeconds(3)
        while (!$accept.Current.IsEnabled -and [DateTime]::UtcNow -lt $until) { Start-Sleep -Milliseconds 50 }
        if (!$accept.Current.IsEnabled) { throw 'Typing without clicking the password field did not enable the Accept button.' }
        $accept.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()
        if (!$proc.WaitForExit(5000)) { throw 'Credential dialog did not close after acceptance.' }
        if (!$AppPid -and ($proc.ExitCode -ne 0 -or $proc.StandardOutput.ReadToEnd() -cne 'synthetic-secret')) {
            throw 'Credential pipe returned an unexpected value.'
        }
        'PASS visible masked Windows dialog accepted input'
        return
    }
    $cancelCondition = [Windows.Automation.PropertyCondition]::new(
        [Windows.Automation.AutomationElement]::NameProperty,
        (-join (0x41e, 0x442, 0x43c, 0x435, 0x43d, 0x430 | ForEach-Object { [char]$_ })))
    $cancel = $dialog.FindFirst([Windows.Automation.TreeScope]::Descendants, $cancelCondition)
    $cancel.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()
    if (!$proc.WaitForExit(5000) -or $proc.ExitCode -ne 1) { throw 'Credential dialog did not cancel.' }
    'PASS native masked Windows dialog and Cancel'
} finally {
    if (!$proc.HasExited) { $proc.Kill() }
}
