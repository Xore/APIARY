package main

// page_notfound.go (#1575): the dashboard's catch-all 404 -- previously a
// bare net/http.NotFound ("404 page not found", no chrome, unstyled) for
// any request routes.go's mux doesn't otherwise match. notFoundPage is
// deliberately just pageMeta: the "notfound" template only calls the
// global template funcs (brandText, brandHTML, presentation, behavior,
// activeBanner) the shared topbar/sidebar partials already rely on
// everywhere else, none of which read a page-specific field.
var pageNotFound = mustReadUI("notfound.html")

type notFoundPage struct {
	pageMeta
}
