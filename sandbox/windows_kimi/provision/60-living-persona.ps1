# 60-living-persona.ps1 - Install the "living persona" daemon.
# A hidden, auto-starting process that continuously simulates Michael Wilson:
# human-curve mouse movement, idle keyboard activity, window focus churn,
# periodic Office/browser interaction. Defeats T1497.002 user-activity checks
# including smoothness analysis (LummaC2-style Euclidean-angle heuristics).
$ErrorActionPreference = 'Continue'
Write-Host '== 60-living-persona =='

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

    const byte VK_SHIFT = 0x10;

    static void TypeChar(char c) {
        // VkKeyScan returns a SHORT: low byte = virtual key, HIGH byte =
        // required modifiers (bit 0 Shift, bit 1 Ctrl, bit 2 Alt). Casting
        // straight to byte kept only the virtual key and dropped the shift
        // state, so every capital and shifted glyph was injected unshifted --
        // 'D' came out 'd', ':' as ';', '+' as '=' (#2448). Synthesize the
        // Shift press/release around the key; refuse Ctrl/Alt-composed
        // characters entirely rather than fire surprise hotkeys.
        short res = VkKeyScan(c);
        if (res == -1) return;           // not typeable on this layout
        if ((res >> 8 & 2) != 0) return; // Ctrl-composed
        if ((res >> 8 & 4) != 0) return; // Alt-composed
        byte vk = (byte)(res & 0xff);
        bool shift = (res >> 8 & 1) != 0;
        if (shift) keybd_event(VK_SHIFT, 0, 0, UIntPtr.Zero);
        keybd_event(vk, 0, 0, UIntPtr.Zero);
        Thread.Sleep(20 + rng.Next(40));
        keybd_event(vk, 0, KEYUP, UIntPtr.Zero);
        if (shift) keybd_event(VK_SHIFT, 0, KEYUP, UIntPtr.Zero);
    }
    [DllImport("user32.dll")] static extern short VkKeyScan(char ch);

    static void TypeSnippet() {
        // Bring up notepad, type a plausible finance note, leave it open.
        var ps = Process.GetProcessesByName("notepad");
        Process np = ps.Length > 0 ? ps[0] : Process.Start("notepad.exe");
        // The old flat 1200 ms sleep left MainWindowHandle at IntPtr.Zero on
        // slow boots: SetForegroundWindow silently no-oped and every
        // keystroke landed in whichever window held focus (#2448). Poll for
        // the handle instead, then refuse to type at all unless notepad
        // actually holds the foreground -- injecting finance jargon into an
        // unrelated application is its own detectable anomaly.
        IntPtr hwnd = IntPtr.Zero;
        for (int i = 0; i < 20; i++) {
            hwnd = np.MainWindowHandle;
            if (hwnd != IntPtr.Zero) break;
            np.Refresh();
            Thread.Sleep(250);
        }
        if (hwnd == IntPtr.Zero) return;            // window never materialized
        if (!SetForegroundWindow(hwnd)) return;     // focus request refused
        Thread.Sleep(400);
        if (GetForegroundWindow() != hwnd) return;  // lost the foreground anyway
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

    // Office-hours weighting: less active 18:00-08:00 EASTERN time, whatever
    // the guest's own timezone setting is (#2448: this read DateTime.Now.Hour
    // -- local time, so the provisioning host's TZ decided what "office
    // hours" meant -- while the comment promised EST).
    static bool WorkHours() {
        try {
            TimeZoneInfo est = TimeZoneInfo.FindSystemTimeZoneById("Eastern Standard Time");
            int h = TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, est).Hour;
            return h >= 8 && h < 18;
        } catch (TimeZoneNotFoundException) {
            return DateTime.Now.Hour >= 8 && DateTime.Now.Hour < 18;
        } catch (InvalidTimeZoneException) {
            return DateTime.Now.Hour >= 8 && DateTime.Now.Hour < 18;
        }
    }

    public static void Main() {
        var sw = Stopwatch.StartNew();
        int idleStreak = 0;
        while (true) {
            bool workHours = WorkHours();
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
Write-Host 'PersonaDaemon compiled.'

# ---------------- Auto-start at logon (interactive session required for
# mouse_event/SendInput to hit the real desktop) ----------------
$action = New-ScheduledTaskAction -Execute "$personaDir\PersonaDaemon.exe"
$trigger = New-ScheduledTaskTrigger -AtLogOn -User 'mwilson'
$settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName 'Windows Shell Experience Helper' `
  -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest -Force | Out-Null

# Benign-looking name in Task Scheduler is intentional camouflage.
Write-Host '== 60-living-persona done =='
