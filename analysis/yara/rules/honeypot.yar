rule HP_Native_PE_Executable {
  meta: severity = "high" description = "Windows PE executable"
  condition: uint16(0) == 0x5a4d
}

rule HP_Native_ELF_Executable {
  meta: severity = "high" description = "Linux ELF executable"
  condition: uint32(0) == 0x464c457f
}

rule HP_Script_Network_Downloader {
  meta: severity = "high" description = "Script downloads additional content"
  strings:
    $curl = /curl[ \t]+(-[^\r\n ]+[ \t]+)*https?:\/\// nocase
    $wget = /wget[ \t]+(-[^\r\n ]+[ \t]+)*https?:\/\// nocase
    $iwr = "Invoke-WebRequest" nocase
    $webclient = "DownloadString(" nocase
  condition: any of them
}

rule HP_PowerShell_Encoded_Execution {
  meta: severity = "critical" description = "Encoded or in-memory PowerShell execution"
  strings:
    $ps = "powershell" nocase
    $enc1 = "-EncodedCommand" nocase
    $enc2 = "FromBase64String" nocase
    $iex = "Invoke-Expression" nocase
  condition: $ps and any of ($enc*) or $ps and $iex
}

rule HP_Reverse_Shell_Primitives {
  meta: severity = "critical" description = "Common reverse-shell primitive"
  strings:
    $devtcp = "/dev/tcp/" nocase
    $nce = /nc(at)?[ \t]+[^\r\n]{0,120}[ \t]-e[ \t]/ nocase
    $bashi = "bash -i" nocase
    $tcpclient = "System.Net.Sockets.TCPClient" nocase
  condition: any of them
}

rule HP_Linux_Persistence_Primitives {
  meta: severity = "high" description = "Linux persistence path or command"
  strings:
    $keys = "authorized_keys" nocase
    $cron = "/etc/cron" nocase
    $systemd = "/etc/systemd/system" nocase
  condition: any of them
}

rule HP_Cryptominer_Indicators {
  meta: severity = "high" description = "Cryptominer or mining-pool indicators"
  strings:
    $xmrig = "xmrig" nocase
    $stratum = "stratum+tcp://" nocase
    $pool = /pool\.(minexmr|supportxmr|nanopool|2miners)\./ nocase
  condition: any of them
}
