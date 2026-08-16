package main

// /sensors (#1538): the per-sensor detail view -- one tab per covered
// sensor, each rendering that sensor's own protocol-specific structured
// fields (mailoney's SMTP sender/recipient/body, http-honeypot's request
// method/headers/body) instead of only the generic cross-sensor shape
// /events already covers. See sensor_detail.go's package comment for the
// design survey (which sensors qualify today, which are deliberately left
// for follow-up) and the extension pattern for adding another sensor tab.
//
// Route templates live in the embedded ui tree; see
// docs/DASHBOARD-RENDER-ENGINE-GUIDE.md §6 step 3. Markup is unchanged.
var pageSensors = mustReadUI("sensors.html")
