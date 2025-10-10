Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class Win32 {
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern int GetWindowTextLength(IntPtr hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);
}
"@ | Out-Null

# Function to get username from process owner via WMI (reliable and works cross-session)
function Get-ProcessOwner {
    param([int]$ProcId)
    try {
        $p = Get-WmiObject Win32_Process -Filter "ProcessId = $ProcId" -ErrorAction Stop
        $out = $p.GetOwner()
        if ($out.Domain -and $out.User) {
            return "$($out.Domain)\$($out.User)"
        } else {
            return "SYSTEM"
        }
    } catch {
        return "Unknown"
    }
}

$windows = New-Object System.Collections.Generic.List[Object]
$ErrorActionPreference = 'SilentlyContinue'

[Win32]::EnumWindows({
    param($hWnd, $lParam)

    try {
        if ([Win32]::IsWindowVisible($hWnd)) {
            $len = [Win32]::GetWindowTextLength($hWnd)
            if ($len -gt 0) {
                $sb = New-Object System.Text.StringBuilder -ArgumentList ($len + 1)
                [Win32]::GetWindowText($hWnd, $sb, $sb.Capacity) | Out-Null
                $title = $sb.ToString().Trim()

                if (-not [string]::IsNullOrWhiteSpace($title)) {
                    [uint32]$procId = 0
                    [Win32]::GetWindowThreadProcessId($hWnd, [ref]$procId) | Out-Null

                    try {
                        $proc = Get-Process -Id $procId -ErrorAction Stop
                        $procName = $proc.ProcessName
                    } catch {
                        $procName = "Unknown"
                    }

                    $user = Get-ProcessOwner -ProcId $procId

                    $windows.Add([PSCustomObject]@{
                        Handle  = ('0x{0:X8}' -f $hWnd.ToInt64())
                        PID     = $procId
                        Process = $procName
                        User    = $user
                        Title   = $title
                    })
                }
            }
        }
    } catch {
        # ignore
    }

    return $true
}, [IntPtr]::Zero) | Out-Null

$windows |
    Sort-Object User, Process, Title |
    Format-Table -AutoSize Handle, PID, Process, User, Title
