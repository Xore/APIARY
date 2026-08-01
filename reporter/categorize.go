package main

// categories maps a sensor + event kind to AbuseIPDB category codes, per
// docs/ip-reporting-plan.md's own table (https://www.abuseipdb.com/categories).
// An event whose (sensor, kind) isn't recognized here maps to nil, which the
// caller treats as "not reportable" -- same conservative-by-default rule as
// event.go's kindOf: guess nothing, skip what isn't confidently classified.
func categories(sensor, kind string) []int {
	switch {
	case sensor == "cowrie" && kind == "login":
		return []int{18, 22} // Brute-Force, SSH
	case sensor == "cowrie" && kind == "command":
		return []int{18, 22}
	case sensor == "dionaea" && kind == "download":
		return []int{20} // Malware
	case sensor == "http-honeypot" || sensor == "api-honeypot":
		if kind == "scan" {
			return []int{21} // Web App Attack
		}
	case sensor == "multipot":
		return []int{14} // Port Scan
	case sensor == "conpot", sensor == "dnp3":
		return []int{14, 15} // Port Scan, Hacking
	}
	return nil
}
