package main

import (
	"encoding/json"
	"net/http"
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
	Country string `json:"country,omitempty"`
	City    string `json:"city,omitempty"`
	Count   int    `json:"count"`
	IPCount int    `json:"ip_count"`
	Events  string `json:"events_url"`
}

func mapPointsGeoJSON(points []mapPoint) mapFeatureCollection {
	out := mapFeatureCollection{Type: "FeatureCollection", Features: make([]mapFeature, 0, len(points))}
	for _, p := range points {
		out.Features = append(out.Features, mapFeature{
			Type:     "Feature",
			Geometry: mapGeometry{Type: "Point", Coordinates: [2]float64{p.Lon, p.Lat}},
			Properties: mapProperties{
				Country: p.Country, City: p.City, Count: p.Count, IPCount: p.IPCount,
				// #228: drills into every event for this city (or country,
				// when GeoIP never resolved a city), not one
				// arbitrarily-chosen IP's events -- matching what the
				// marker is now actually showing.
				Events: mapPointEventsURL(p.City, p.Country),
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
