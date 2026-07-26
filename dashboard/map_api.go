package main

import (
	"encoding/json"
	"net/http"
	"net/url"
)

type mapFeatureCollection struct {
	Type     string       `json:"type"`
	Features []mapFeature `json:"features"`
}

type mapFeature struct {
	Type       string        `json:"type"`
	Geometry   mapGeometry   `json:"geometry"`
	Properties mapProperties `json:"properties"`
}

type mapGeometry struct {
	Type        string     `json:"type"`
	Coordinates [2]float64 `json:"coordinates"` // GeoJSON is longitude, latitude.
}

type mapProperties struct {
	IP       string `json:"ip"`
	Country  string `json:"country,omitempty"`
	City     string `json:"city,omitempty"`
	ASN      uint   `json:"asn,omitempty"`
	Org      string `json:"organization,omitempty"`
	Provider string `json:"provider_type,omitempty"`
	Intel    string `json:"intel,omitempty"`
	Count    int    `json:"count"`
	Events   string `json:"events_url"`
}

func mapPointsGeoJSON(points []mapPoint) mapFeatureCollection {
	out := mapFeatureCollection{Type: "FeatureCollection", Features: make([]mapFeature, 0, len(points))}
	for _, p := range points {
		out.Features = append(out.Features, mapFeature{
			Type:     "Feature",
			Geometry: mapGeometry{Type: "Point", Coordinates: [2]float64{p.Lon, p.Lat}},
			Properties: mapProperties{
				IP: p.IP, Country: p.Country, City: p.City, ASN: p.ASN, Org: p.Org,
				Provider: p.Provider, Intel: p.Intel, Count: p.Count,
				Events: "/investigate/ip/" + url.PathEscape(p.IP),
			},
		})
	}
	return out
}

func (s *store) serveMapPoints(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/geo+json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(mapPointsGeoJSON(s.get().MapPoints))
}
