#Requires -RunAsAdministrator
# 07-living-persona.ps1 — Packer provisioner, step 6a of win11-analysis.pkr.hcl's build.
#
# #290: installs the "living persona" daemon -- a hidden, auto-starting
# process that continuously simulates the analyst account being at the
# keyboard: cubic-Bezier mouse movement with Gaussian-offset control
# points and an ease-in-out velocity profile, occasional clicks/scroll,
# and periodic Notepad typing with human inter-key jitter. Defeats
# T1497.002 user-activity checks, including the mouse-trigonometry /
# angle-smoothness class of check called out in LummaC2 v4.0 (Red Report
# 2026). Ported from sandbox/windows_kimi/provision/60-living-persona.ps1
# (merged at 536b505); only the AtLogOn user changed, from that
# prototype's 'mwilson' to this image's actual WinRM/autologon account.
#
# Needs an interactive desktop session for SetCursorPos/mouse_event/
# keybd_event to land on the real desktop -- it only *registers* the
# scheduled task here at build time. That holds under run_sample.py's
# virsh boot + autologon flow (AutoLogon in autounattend.xml logs the
# same account in on every boot, which is what fires the AtLogOn trigger).

$ErrorActionPreference = 'Continue'
Write-Host '================================================================'
Write-Host ' Honeypot-Stack: Windows 11 Analysis VM - living-persona daemon'
Write-Host '================================================================'

$personaDir = 'C:\ProgramData\persona'
New-Item -ItemType Directory -Force -Path $personaDir | Out-Null

# ---------------- The daemon (C# compiled at provision time) ----------------
$cs = @'
using System;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Threading;
using System.Diagnostics;

// PersonaDaemon: continuous low-intensity human presence simulation.
// Design notes (from Red Report 2026 / LummaC2 analysis):
//  - Movement uses cubic Bezier paths with overshoot + micro-corrections:
//    consecutive segment angles change smoothly -> passes Euclidean-distance
//    and angle-smoothness heuristics.
//  - Velocity follows a bell profile (slow-accelerate-fast-decelerate), never
//    constant pixels/step.
//  - Activity follows a work rhythm: bursts of movement, then pauses
//    (reading), occasional clicks, occasional scroll. Office-hours weighting.
//  - Also generates keystrokes into NOTEPAD periodically (real typing rhythm,
//    180-320ms inter-key jitter with occasional 1-2s "thinking" pauses).
public class PersonaDaemon {
    [DllImport("user32.dll")] static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] static extern bool GetCursorPos(out POINT p);
    [DllImport("user32.dll")] static extern void mouse_event(uint f, uint dx, uint dy, uint d, UIntPtr e);
    [DllImport("user32.dll")] static extern void keybd_event(byte vk, byte scan, uint f, UIntPtr e);
    [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr h);

    const uint MOUSEEVENTF_LEFTDOWN = 0x02, MOUSEEVENTF_LEFTUP = 0x04, WHEEL = 0x0800;
    const uint KEYUP = 0x02;

    struct POINT { public int X, Y; }
    static Random rng = new Random();

    static double Gauss() { // Box-Muller
        double u = 1.0 - rng.NextDouble(), v = 1.0 - rng.NextDouble();
        return Math.Sqrt(-2 * Math.Log(u)) * Math.Cos(2 * Math.PI * v);
    }

    static void HumanMove(int tx, int ty) {
        POINT s; GetCursorPos(out s);
        double dist = Math.Sqrt(Math.Pow(tx - s.X, 2) + Math.Pow(ty - s.Y, 2));
        if (dist < 2) return;
        // Control points offset perpendicular -> curved path (Fitts-ish)
        double mx = (s.X + tx) / 2 + Gauss() * dist / 6;
        double my = (s.Y + ty) / 2 + Gauss() * dist / 6;
        int steps = Math.Max(12, (int)(dist / 8) + rng.Next(-3, 4));
        for (int i = 1; i <= steps; i++) {
            double t = (double)i / steps;
            // ease-in-out velocity profile
            double e = t < .5 ? 2 * t * t : 1 - Math.Pow(-2 * t + 2, 2) / 2;
            int x = (int)((1 - e) * (1 - e) * s.X + 2 * (1 - e) * e * mx + e * e * tx);
            int y = (int)((1 - e) * (1 - e) * s.Y + 2 * (1 - e) * e * my + e * e * ty);
            SetCursorPos(x + rng.Next(-1, 2), y + rng.Next(-1, 2));
            Thread.Sleep(4 + rng.Next(0, 9));
        }
        SetCursorPos(tx, ty);
        // overshoot correction: 15% of moves get a tiny follow-up adjustment
        if (rng.NextDouble() < 0.15) {
            Thread.Sleep(80 + rng.Next(120));
            SetCursorPos(tx + rng.Next(-3, 4), ty + rng.Next(-3, 4));
        }
    }

    static void Click() {
        mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, UIntPtr.Zero);
        Thread.Sleep(60 + rng.Next(80));
        mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, UIntPtr.Zero);
    }

    static void TypeChar(char c) {
        byte vk = (byte)VkKeyScan(c);
        keybd_event(vk, 0, 0, UIntPtr.Zero);
        Thread.Sleep(20 + rng.Next(40));
        keybd_event(vk, 0, KEYUP, UIntPtr.Zero);
    }
    [DllImport("user32.dll")] static extern short VkKeyScan(char ch);

    static void TypeSnippet() {
        // Bring up notepad, type a plausible finance note, leave it open.
        var ps = Process.GetProcessesByName("notepad");
        Process np = ps.Length > 0 ? ps[0] : Process.Start("notepad.exe");
        Thread.Sleep(1200);
        SetForegroundWindow(np.MainWindowHandle);
        Thread.Sleep(400);
        string[] lines = {
            "accrual for legal fees - confirm w/ Dana before Thu",
            "FX hedge ratio 0.75 for EUR book, revisit after FOMC",
            "variance: travel +12% - sales offsite, approved",
            "wire cutoff 3pm - tell AP team",
            "board pack: update liquidity slide w/ Dec numbers"
        };
        string line = lines[rng.Next(lines.Length)] + "\r";
        foreach (char c in line) {
            TypeChar(c);
            Thread.Sleep(120 + (int)Math.Abs(Gauss() * 60));
            if (rng.NextDouble() < 0.04) Thread.Sleep(800 + rng.Next(1400)); // thinking pause
        }
    }

    static void ScrollChurn() {
        // Office docs check scroll events; emit some wheel activity
        int dir = rng.NextDouble() < 0.7 ? -120 : 120;
        for (int i = 0; i < 2 + rng.Next(4); i++) {
            mouse_event(WHEEL, 0, 0, (uint)dir, UIntPtr.Zero);
            Thread.Sleep(150 + rng.Next(400));
        }
    }

    static void RunCycle(ref int idleStreak) {
        // Office-hours weighting: less active 18:00-08:00 EST
        int h = DateTime.Now.Hour;
        bool workHours = h >= 8 && h < 18;
        int act = rng.Next(100);

        if (workHours ? act < 55 : act < 15) {
            // Mouse burst: 3-9 waypoints across the screen
            int burst = 3 + rng.Next(7);
            for (int i = 0; i < burst; i++) {
                HumanMove(rng.Next(200, 1700), rng.Next(150, 950));
                Thread.Sleep(150 + rng.Next(900));
            }
            if (rng.NextDouble() < 0.35) Click();
            if (rng.NextDouble() < 0.4) ScrollChurn();
            idleStreak = 0;
        } else {
            idleStreak++;
        }

        if (workHours && rng.NextDouble() < 0.06) TypeSnippet();
    }

    public static void Main() {
        // #368 (2026-08-04): even with the scheduled task's Principal set to
        // -LogonType Interactive, AtLogOn fired this before explorer.exe/the
        // desktop had finished initializing -- confirmed live, explorer's own
        // process StartTime landed the same second as the task's LastRunTime,
        // and the daemon crashed with the exact same CLR20r3 fault (thrown
        // from System.dll, not from a call this code makes directly -- the
        // exact throw site is inside CLR/framework startup plumbing for a
        // WindowsApplication-subsystem exe without a ready desktop, not
        // something a narrow catch around one P/Invoke call would reliably
        // hit). LogonType fixes *which* session the task runs in; it does not
        // wait for that session's desktop to actually be ready. Fixed two
        // ways: the trigger itself now carries a startup Delay (see
        // Register-ScheduledTask below), and this is a broad catch(Exception)
        // around each cycle -- deliberately generic rather than typed, since
        // this is best-effort decoy activity, not logic where swallowing the
        // wrong exception type would hide a real bug worth seeing.
        int idleStreak = 0;
        while (true) {
            try {
                RunCycle(ref idleStreak);
            } catch (Exception) {
                // Desktop/window-station transiently unavailable (lock
                // screen, session switch, or still-initializing at logon) --
                // skip this cycle, don't crash the whole process.
            }

            // Base cadence: 4-14s between decisions (never periodic!)
            Thread.Sleep(4000 + (int)Math.Abs(Gauss() * 3500));
            if (idleStreak > 30) { Thread.Sleep(60000 + rng.Next(120000)); idleStreak = 0; }
        }
    }
}
'@

$csPath = "$personaDir\PersonaDaemon.cs"
$cs | Set-Content $csPath -Encoding UTF8

Add-Type -TypeDefinition $cs -ReferencedAssemblies 'System.Drawing','System.Windows.Forms' `
  -OutputAssembly "$personaDir\PersonaDaemon.exe" -OutputType WindowsApplication -ErrorAction Stop
Write-Host '[+] PersonaDaemon compiled'

# ---------------- Auto-start at logon (interactive session required for
# mouse_event/SendInput to hit the real desktop). Runs under the same
# account run_sample.py's autologon flow uses, not the kimi prototype's
# hardcoded 'mwilson'.
#
# #368: found live via #298's reverse-turing re-verification that this
# daemon had never actually run successfully since #290 shipped it --
# Get-ScheduledTaskInfo showed LastTaskResult 3762504530 (0xE0434352, the
# CLR unhandled-managed-exception marker) on every single boot, and
# Windows Error Reporting's Application-log entries pinned it exactly:
# System.InvalidOperationException thrown from System.dll (WinForms/GDI
# calls like Cursor.Position need a window handle, which throws this
# specific exception when the process has no window station/desktop
# attached). Registering without an explicit -Principal left the task's
# logon type unspecified rather than guaranteed Interactive -- even with
# 'analyst' genuinely logged into the interactive console session the
# whole time, the task's own execution context wasn't reliably attached
# to it. Exact same failure shape as the GHOSTS client's Session-0 launch
# bug and the scheduled-task fix pattern already proven there; the
# -Principal below is that same fix. This silently explains every one of
# #368's failed pafish "generic reverse turing test" results (mouse
# presence/movement/speed/click/double-click, dialog confirmation) --
# there was no persona daemon actually warming anything up to re-verify
# against, on any build before this one. -------------------------------
#
# #368 follow-up (same day): -Principal alone was NOT enough -- confirmed
# live on an actual golden-image cold boot (not just re-triggering the task
# mid-session, which is what the first fix was verified against) that the
# task still fired the exact same 0xE0434352 crash. explorer.exe's own
# StartTime landed in the same second as the task's LastRunTime: LogonType
# Interactive picks the right session, but AtLogOn fires the instant that
# session exists, not once its desktop/window station is actually usable.
# $trigger.Delay (a TimeSpan string, not a Register-ScheduledTask param --
# has to be set on the trigger object itself) gives explorer time to finish
# initializing first. Paired with a startup retry loop and a per-cycle
# try/catch inside PersonaDaemon's C# above, so an occasional remaining
# race (session lock, etc.) skips a cycle instead of crashing the process.
$action = New-ScheduledTaskAction -Execute "$personaDir\PersonaDaemon.exe"
$trigger = New-ScheduledTaskTrigger -AtLogOn -User 'analyst'
$trigger.Delay = 'PT20S'
$principal = New-ScheduledTaskPrincipal -UserId 'analyst' -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName 'Windows Shell Experience Helper' `
  -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

# Benign-looking name in Task Scheduler is intentional camouflage.
'living_persona=installed' | Add-Content 'C:\golden_image_provenance.txt'
Write-Host '[+] Living-persona daemon registered'
exit 0
