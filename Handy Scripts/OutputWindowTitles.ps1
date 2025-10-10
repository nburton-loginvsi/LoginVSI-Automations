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

$windows = New-Object System.Collections.Generic.List[Object]

# Suppress all non-terminating errors inside script block
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
                    $windows.Add([PSCustomObject]@{
                        Handle  = ('0x{0:X8}' -f $hWnd.ToInt64())
                        PID     = $procId
                        Process = $procName
                        Title   = $title
                    })
                }
            }
        }
    } catch {
        # silently ignore any exceptions per window
    }

    return $true
}, [IntPtr]::Zero) | Out-Null

$windows |
    Sort-Object Process, Title |
    Format-Table -AutoSize Handle, PID, Process, Title
