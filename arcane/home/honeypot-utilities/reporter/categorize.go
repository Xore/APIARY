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
		switch kind {
		case "scan":
			return []int{21} // Web App Attack
		case "login":
			return []int{18} // Brute-Force -- a fake web login form credential
			// attempt, same underlying abuse as cowrie's SSH login (#68 review
			// found this combination falling through to nil/unreported).
		}
	case sensor == "multipot":
		return []int{14} // Port Scan
	case sensor == "conpot", sensor == "dnp3":
		return []int{14, 15} // Port Scan, Hacking
	case sensor == "suricata":
		return suricataCategories(kind)
	}
	return nil
}

// suricataCategories maps Suricata's own alert classification (the human-
// readable "category" text from classification.config, not the raw
// classtype slug) to AbuseIPDB codes. This is Suricata's fixed, documented
// vocabulary -- not something invented here -- confirmed directly against
// real alerts captured on this deployment: "Potentially Bad Traffic" (ET
// SCAN rules), "Attempted Administrator Privilege Gain", "Misc Attack", and
// "Generic Protocol Command Decode" (Suricata's own decoder noticing a
// truncated/malformed packet -- not attacker behavior, explicitly excluded
// below) all appear live in eve.json on this host.
//
// Deliberately conservative, same rule as the honeypot-sensor cases above:
// a category this switch doesn't recognize -- or recognizes as benign/too
// vague to act on -- returns nil rather than a guessed catch-all code.
func suricataCategories(category string) []int {
	switch category {
	case "Attempted Administrator Privilege Gain", "Successful Administrator Privilege Gain",
		"Attempted User Privilege Gain", "Successful User Privilege Gain",
		"Attempted Information Leak", "Information Leak Detected", "Large Scale Information Leak",
		"Misc Attack":
		return []int{15} // Hacking
	case "Web Application Attack":
		return []int{21} // Web App Attack
	case "Attempted Denial of Service", "Detection of a Denial of Service Attack":
		return []int{4} // DDoS Attack
	case "A Network Trojan was Detected", "Malware Command and Control Activity Detected":
		return []int{20} // Exploited Host
	case "Attempt to Login By a Default Username and Password":
		return []int{18} // Brute-Force
	case "Potentially Bad Traffic", "A Network Scan or Probe was Detected", "Detection of a Network Scan":
		return []int{14} // Port Scan
	default:
		// Includes "Generic Protocol Command Decode" (Suricata's own
		// decoder flagging a truncated/malformed packet -- confirmed the
		// dominant alert category on this deployment, and not evidence of
		// attacker intent), "Not Suspicious Traffic", "Unknown Traffic",
		// and anything else this switch doesn't confidently recognize.
		return nil
	}
}
