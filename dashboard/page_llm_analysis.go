package main

// /llm-analysis (#150): llm-worker's guarded model output, delivered to the
// dashboard by Elasticsearch polling (see llm_analysis.go's package comment
// for the transport decision). Markup follows /ml-anomalies: server-
// rendered from a cache, refreshed on page load.
var pageLLMAnalysis = mustReadUI("llm_analysis.html")
