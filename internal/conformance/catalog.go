package conformance

// Catalog is every documented behaviour the suite knows about, assembled from
// the per-chapter slices. Adding a chapter means adding a file and a line here.
var Catalog = func() []Case {
	var all []Case
	all = append(all, oidcCore...)
	return all
}()
