#Requires -RunAsAdministrator
# 12-display-resolution.ps1 -- Packer provisioner, #368 remediation item 2.
#
# win11-kvm.xml's <video><resolution x='1920' y='1080'/> hint (also #368)
# already gets QEMU's stdvga boot-time framebuffer to a real 1920x1080 --
# confirmed live via `virsh screenshot`, holding from the OVMF boot screen
# onward. That is NOT what Windows' own desktop actually renders at, though:
# Win32_VideoController correctly reports 1920x1080 (it reads the adapter's
# current mode), but every GDI/WinForms-level API
# ([System.Windows.Forms.Screen]::PrimaryScreen.Bounds, SystemInformation.
# VirtualScreen, Screen.AllScreens) consistently reported 1280x800 instead --
# confirmed live, in-session (not a WinRM Session-0 misread; #696 already
# ruled that out as the explanation here). Root cause: the registry key
# under HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Configuration,
# keyed by a synthetic MSBDD_NOEDID_... profile name (Microsoft Basic
# Display Driver, no EDID -- there is no real monitor to negotiate a mode
# with), holds a stale 1280x800 desktop size that predates this image ever
# getting the <resolution> hint above. Windows does not re-negotiate this on
# its own; it just keeps using the last mode it saved for that profile.
#
# Fix: call ChangeDisplaySettings via P/Invoke with CDS_UPDATEREGISTRY, the
# same underlying mechanism Settings > Display > Resolution uses -- not a
# registry-blob edit. Confirmed live: result 0 (success), and a fresh
# in-session Screen.PrimaryScreen.Bounds query afterward reads 1920x1080,
# persisting across a fresh WinRM session (not just the process that set
# it).

$ErrorActionPreference = 'Stop'
Write-Host '================================================================'
Write-Host ' Honeypot-Stack: Windows 11 Analysis VM - Display Resolution'
Write-Host '================================================================'

Add-Type @"
using System;
using System.Runtime.InteropServices;

public class HoneypotDisplaySettings {
    [StructLayout(LayoutKind.Sequential)]
    public struct DEVMODE {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string dmDeviceName;
        public short dmSpecVersion;
        public short dmDriverVersion;
        public short dmSize;
        public short dmDriverExtra;
        public int dmFields;
        public int dmPositionX;
        public int dmPositionY;
        public int dmDisplayOrientation;
        public int dmDisplayFixedOutput;
        public short dmColor;
        public short dmDuplex;
        public short dmYResolution;
        public short dmTTOption;
        public short dmCollate;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string dmFormName;
        public short dmLogPixels;
        public int dmBitsPerPel;
        public int dmPelsWidth;
        public int dmPelsHeight;
        public int dmDisplayFlags;
        public int dmDisplayFrequency;
        public int dmICMMethod;
        public int dmICMIntent;
        public int dmMediaType;
        public int dmDitherType;
        public int dmReserved1;
        public int dmReserved2;
        public int dmPanningWidth;
        public int dmPanningHeight;
    }

    [DllImport("user32.dll")]
    public static extern int EnumDisplaySettings(string deviceName, int modeNum, ref DEVMODE devMode);

    [DllImport("user32.dll")]
    public static extern int ChangeDisplaySettings(ref DEVMODE devMode, int flags);

    public const int ENUM_CURRENT_SETTINGS = -1;
    public const int CDS_UPDATEREGISTRY = 0x01;
    public const int DM_PELSWIDTH = 0x80000;
    public const int DM_PELSHEIGHT = 0x100000;
}
"@

$cur = New-Object HoneypotDisplaySettings+DEVMODE
[HoneypotDisplaySettings]::EnumDisplaySettings($null, [HoneypotDisplaySettings]::ENUM_CURRENT_SETTINGS, [ref]$cur) | Out-Null
Write-Host "[*] Current mode before change: $($cur.dmPelsWidth)x$($cur.dmPelsHeight)"

$new = $cur
$new.dmPelsWidth = 1920
$new.dmPelsHeight = 1080
# Only these two fields -- leaving dmBitsPerPel/dmDisplayFrequency etc. as
# whatever EnumDisplaySettings already populated them with, same technique
# confirmed live: setting just PELSWIDTH|PELSHEIGHT and nothing else still
# succeeded (result 0) rather than needing every DEVMODE field populated.
$new.dmFields = [HoneypotDisplaySettings]::DM_PELSWIDTH -bor [HoneypotDisplaySettings]::DM_PELSHEIGHT

$result = [HoneypotDisplaySettings]::ChangeDisplaySettings([ref]$new, [HoneypotDisplaySettings]::CDS_UPDATEREGISTRY)
if ($result -ne 0) {
    Write-Host "[!] ChangeDisplaySettings returned $result (0=success) -- resolution not changed"
    exit 1
}
Write-Host '[+] ChangeDisplaySettings succeeded (result 0)'

Start-Sleep -Seconds 2
Add-Type -AssemblyName System.Windows.Forms
$s = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
Write-Host "[*] Screen.PrimaryScreen.Bounds after change: $($s.Width)x$($s.Height)"
if ($s.Width -ne 1920 -or $s.Height -ne 1080) {
    Write-Host '[!] Bounds does not read 1920x1080 after the change -- check manually'
    exit 1
}
Write-Host '[+] Desktop resolution verified at 1920x1080.'
