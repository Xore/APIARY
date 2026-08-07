package main

// /agent-campaigns (#154 phase 5): agent-intrusion-worker's correlated
// campaign verdicts, delivered to the dashboard by Elasticsearch polling
// (see agent_campaigns.go's package comment for the transport decision).
// Markup follows the read-only diagnostics pages (ml-anomalies,
// source-health): server-rendered from a cache, refreshed on page load.
var pageAgentCampaigns = mustReadUI("agent_campaigns.html")
