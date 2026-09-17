package conformance

import "sort"

// Configuration names the way the reference container a case is recorded
// against was started.
//
// **It exists because a golden's bytes are a function of the container's
// command line in more than one place, and until 2026-09-16 nothing said
// which.** Two measured instances, a week apart:
//
//   - the whole management surface exists only under `--health-enabled` or
//     `--metrics-enabled`, and two of its responses are functions of *which* -
//     the index page lists exactly the endpoints that are switched on, and
//     `/health`'s check list gains a database entry only when metrics is on;
//   - the theme resource route's `Cache-Control` is `no-cache` under
//     `start-dev` and `max-age=2592000` under `start`, one image, measured on
//     two containers.
//
// The first is **visible** - nothing on port 9000 exists without the option, so
// a reader who wonders knows to ask. The second is not: a `Cache-Control`
// header on a static file reads as a property of the product. That asymmetry is
// why this is a value spelled into the golden file rather than a field the
// catalogue keeps to itself. See F245 and F250.
//
// The value is spelled as the command line a person would type, so a golden is
// reproducible by hand from the file alone:
//
//	# GET /health
//	# recorded-with: start-dev --health-enabled
//
// Keycloak takes these as `KC_*` environment variables in a container, which is
// what keycloakEnv turns them into. The spelling is the CLI's because the file
// is read by people.
type Configuration string

const (
	// StartDevHealthMetrics is the configuration every golden in this tree was
	// recorded under until 2026-09-16, and it is still the default: a case that
	// declares nothing gets it.
	//
	// Both options are on because the management chapter enumerates the surface
	// with both, and the metrics half of that chapter cannot be measured
	// without `--metrics-enabled` at all - `/metrics` under health alone is the
	// ordinary 53-byte 404, which is a fact about the *other* configuration.
	StartDevHealthMetrics Configuration = "start-dev --health-enabled --metrics-enabled"

	// StartDevHealth is the option set Gloak serves. Gloak keeps no counters,
	// so it has no `--metrics-enabled`; a Keycloak started this way answers
	// `/metrics` with the ordinary 53-byte 404, serves a 120-byte index page
	// listing `/health` alone, and answers `/health` with two checks rather
	// than three. All three were measured on 2026-09-16.
	StartDevHealth Configuration = "start-dev --health-enabled"
)

// DefaultConfiguration is what a case that declares nothing is recorded under.
//
// It is the both-options one rather than the one Gloak serves, and that is
// deliberate: changing the default would re-record 1136 goldens to answer a
// question eight of them ask. A default that moves the whole tree is a default
// nobody can review.
const DefaultConfiguration = StartDevHealthMetrics

// configurationEnv is the container environment each configuration is started
// with, beyond the bootstrap administrator every container gets.
//
// **It is pinned whole by TestConfigurationEnvironmentsArePinned rather than
// checked entry by entry**, which is the shape internal/model uses for the
// providers with no mapper set: an entry arriving and an entry leaving each
// fail on their own. A table that is only read by the code that writes it is a
// table that can be edited into saying anything.
//
// It lives here rather than in record_test.go because that file carries the
// `docker` build tag, and logic nothing can test without Docker is logic
// nothing tests - the reason Target and recordedHeaders live outside it too. A
// mutation collapsing this map to one entry would survive every test in a
// package that cannot compile the file it was written in.
var configurationEnv = map[Configuration]map[string]string{
	StartDevHealthMetrics: {
		"KC_HEALTH_ENABLED":  "true",
		"KC_METRICS_ENABLED": "true",
	},
	StartDevHealth: {
		"KC_HEALTH_ENABLED": "true",
	},
}

// Configurations is every configuration a case may declare, sorted so the
// recorder's log and any report over them is stable.
func Configurations() []Configuration {
	out := make([]Configuration, 0, len(configurationEnv))
	for cfg := range configurationEnv {
		out = append(out, cfg)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ConfigurationOf returns the configuration c's golden is recorded under.
//
// **It reads one field and must not read any other.** This is the second
// predicate in this package that decides which container a case's request
// reaches, after Target, and the first one was got wrong in exactly the way
// this comment exists to prevent: narrowing Target to
// `c.ManagementPort && c.Status == Implemented` compiled, survived 26 subtests
// because Implemented is Status's zero value, and would have had `make record`
// rewrite eight goldens from the wrong port with the whole tree green.
//
// The same shape is available here and it is worse, because a wrong answer
// starts a *differently configured container* rather than connecting to the
// wrong socket of the right one. A predicate reading ManagementPort would put
// every management case on one configuration, which is precisely what this
// field exists to stop: the metrics cases need `--metrics-enabled` and the
// health cases need it off. A predicate reading Status would freeze a case's
// configuration at the moment it was promoted.
//
// TestConfigurationOfFollowsTheDeclaration runs it over both flags and all
// three statuses for that reason, and
// TestEveryGoldenNamesTheConfigurationItsCaseDeclares is the other side: the
// file says what the case declares, or the tree is wrong.
func ConfigurationOf(c Case) Configuration {
	if c.Configuration == "" {
		return DefaultConfiguration
	}
	return c.Configuration
}

// keycloakEnv returns the environment a container for cfg is started with, and
// reports whether cfg is one this package declares.
//
// An undeclared configuration is refused rather than silently started with no
// options: a container with neither option has no management port at all, so
// the first management request would get an empty reply and a recorder failure
// forty seconds into a fourteen-minute run. F249 records that measurement.
func keycloakEnv(cfg Configuration) (map[string]string, bool) {
	env, ok := configurationEnv[cfg]
	return env, ok
}
