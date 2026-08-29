package admin

// Keycloak's RealmRepresentation, and the four narrower bodies the same
// endpoints serve to a caller that may not see the whole thing.
//
// The field order below is transcribed from a recorded
// GET /admin/realms/{realm} and is the contract: Go emits struct fields in
// declaration order, and that is the only thing reproducing Keycloak's key
// order. Moving a field is a silent divergence, which is why
// realmrep_test.go asserts the marshalled key list rather than a few spot
// values. See "Realms" in
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.

// realmRepresentation is the full body, 104 keys on a created realm and 106 on
// master, whose displayName and displayNameHtml are set.
//
// Fields are values rather than pointers throughout, with two exceptions and no
// omitempty on anything else: every key was measured present, including the
// false booleans, the zero integers and the empty arrays, and omitempty drops
// all three.
//
// **supportedLocales is deliberately absent.** The full body has no such key
// when internationalizationEnabled is false, while the two reduced bodies below
// emit it as []. That is why they are separate structs rather than this one with
// a flag: one field cannot be both absent and empty.
type realmRepresentation struct {
	ID    string `json:"id"`
	Realm string `json:"realm"`
	// Pointers, not strings with omitempty. Measured absent on a created realm
	// and present on master, in this position, on every shape that carries
	// them - and `PUT {"displayName":""}` was measured leaving the key present
	// with an empty value, which omitempty drops. Absent and empty are two
	// different observable states, so the type has to distinguish them.
	DisplayName     *string `json:"displayName,omitempty"`
	DisplayNameHTML *string `json:"displayNameHtml,omitempty"`

	NotBefore                           int    `json:"notBefore"`
	DefaultSignatureAlgorithm           string `json:"defaultSignatureAlgorithm"`
	RevokeRefreshToken                  bool   `json:"revokeRefreshToken"`
	RefreshTokenMaxReuse                int    `json:"refreshTokenMaxReuse"`
	AccessTokenLifespan                 int    `json:"accessTokenLifespan"`
	AccessTokenLifespanForImplicitFlow  int    `json:"accessTokenLifespanForImplicitFlow"`
	SSOSessionIdleTimeout               int    `json:"ssoSessionIdleTimeout"`
	SSOSessionMaxLifespan               int    `json:"ssoSessionMaxLifespan"`
	SSOSessionIdleTimeoutRememberMe     int    `json:"ssoSessionIdleTimeoutRememberMe"`
	SSOSessionMaxLifespanRememberMe     int    `json:"ssoSessionMaxLifespanRememberMe"`
	OfflineSessionIdleTimeout           int    `json:"offlineSessionIdleTimeout"`
	OfflineSessionMaxLifespanEnabled    bool   `json:"offlineSessionMaxLifespanEnabled"`
	OfflineSessionMaxLifespan           int    `json:"offlineSessionMaxLifespan"`
	ClientSessionIdleTimeout            int    `json:"clientSessionIdleTimeout"`
	ClientSessionMaxLifespan            int    `json:"clientSessionMaxLifespan"`
	ClientOfflineSessionIdleTimeout     int    `json:"clientOfflineSessionIdleTimeout"`
	ClientOfflineSessionMaxLifespan     int    `json:"clientOfflineSessionMaxLifespan"`
	AccessCodeLifespan                  int    `json:"accessCodeLifespan"`
	AccessCodeLifespanUserAction        int    `json:"accessCodeLifespanUserAction"`
	AccessCodeLifespanLogin             int    `json:"accessCodeLifespanLogin"`
	ActionTokenGeneratedByAdminLifespan int    `json:"actionTokenGeneratedByAdminLifespan"`
	ActionTokenGeneratedByUserLifespan  int    `json:"actionTokenGeneratedByUserLifespan"`
	OAuth2DeviceCodeLifespan            int    `json:"oauth2DeviceCodeLifespan"`
	OAuth2DevicePollingInterval         int    `json:"oauth2DevicePollingInterval"`
	Enabled                             bool   `json:"enabled"`
	SSLRequired                         string `json:"sslRequired"`
	RegistrationAllowed                 bool   `json:"registrationAllowed"`
	RegistrationEmailAsUsername         bool   `json:"registrationEmailAsUsername"`
	RememberMe                          bool   `json:"rememberMe"`
	VerifyEmail                         bool   `json:"verifyEmail"`
	LoginWithEmailAllowed               bool   `json:"loginWithEmailAllowed"`
	DuplicateEmailsAllowed              bool   `json:"duplicateEmailsAllowed"`
	ResetPasswordAllowed                bool   `json:"resetPasswordAllowed"`
	EditUsernameAllowed                 bool   `json:"editUsernameAllowed"`
	BruteForceProtected                 bool   `json:"bruteForceProtected"`
	PermanentLockout                    bool   `json:"permanentLockout"`
	MaxTemporaryLockouts                int    `json:"maxTemporaryLockouts"`
	BruteForceStrategy                  string `json:"bruteForceStrategy"`
	MaxFailureWaitSeconds               int    `json:"maxFailureWaitSeconds"`
	MinimumQuickLoginWaitSeconds        int    `json:"minimumQuickLoginWaitSeconds"`
	WaitIncrementSeconds                int    `json:"waitIncrementSeconds"`
	QuickLoginCheckMilliSeconds         int    `json:"quickLoginCheckMilliSeconds"`
	MaxDeltaTimeSeconds                 int    `json:"maxDeltaTimeSeconds"`
	FailureFactor                       int    `json:"failureFactor"`
	MaxSecondaryAuthFailures            int    `json:"maxSecondaryAuthFailures"`

	// DefaultRole is derived from the realm's default-roles-{name} role rather
	// than stored: its id and containerId are the store's, so a copy written
	// into the settings blob would be a second truth able to go stale. It is a
	// pointer only so that a realm whose default role has not been created yet
	// marshals as null rather than as a six-key object of empty strings.
	DefaultRole *roleRepresentation `json:"defaultRole"`

	RequiredCredentials                                       []string `json:"requiredCredentials"`
	OTPPolicyType                                             string   `json:"otpPolicyType"`
	OTPPolicyAlgorithm                                        string   `json:"otpPolicyAlgorithm"`
	OTPPolicyInitialCounter                                   int      `json:"otpPolicyInitialCounter"`
	OTPPolicyDigits                                           int      `json:"otpPolicyDigits"`
	OTPPolicyLookAheadWindow                                  int      `json:"otpPolicyLookAheadWindow"`
	OTPPolicyPeriod                                           int      `json:"otpPolicyPeriod"`
	OTPPolicyCodeReusable                                     bool     `json:"otpPolicyCodeReusable"`
	OTPSupportedApplications                                  []string `json:"otpSupportedApplications"`
	WebAuthnPolicyRPEntityName                                string   `json:"webAuthnPolicyRpEntityName"`
	WebAuthnPolicySignatureAlgorithms                         []string `json:"webAuthnPolicySignatureAlgorithms"`
	WebAuthnPolicyRPID                                        string   `json:"webAuthnPolicyRpId"`
	WebAuthnPolicyAttestationConveyancePreference             string   `json:"webAuthnPolicyAttestationConveyancePreference"`
	WebAuthnPolicyAuthenticatorAttachment                     string   `json:"webAuthnPolicyAuthenticatorAttachment"`
	WebAuthnPolicyRequireResidentKey                          string   `json:"webAuthnPolicyRequireResidentKey"`
	WebAuthnPolicyResidentKey                                 string   `json:"webAuthnPolicyResidentKey"`
	WebAuthnPolicyUserVerificationRequirement                 string   `json:"webAuthnPolicyUserVerificationRequirement"`
	WebAuthnPolicyCreateTimeout                               int      `json:"webAuthnPolicyCreateTimeout"`
	WebAuthnPolicyAvoidSameAuthenticatorRegister              bool     `json:"webAuthnPolicyAvoidSameAuthenticatorRegister"`
	WebAuthnPolicyAcceptableAaguids                           []string `json:"webAuthnPolicyAcceptableAaguids"`
	WebAuthnPolicyExtraOrigins                                []string `json:"webAuthnPolicyExtraOrigins"`
	WebAuthnPolicyPasswordlessRPEntityName                    string   `json:"webAuthnPolicyPasswordlessRpEntityName"`
	WebAuthnPolicyPasswordlessSignatureAlgorithms             []string `json:"webAuthnPolicyPasswordlessSignatureAlgorithms"`
	WebAuthnPolicyPasswordlessRPID                            string   `json:"webAuthnPolicyPasswordlessRpId"`
	WebAuthnPolicyPasswordlessAttestationConveyancePreference string   `json:"webAuthnPolicyPasswordlessAttestationConveyancePreference"`
	WebAuthnPolicyPasswordlessAuthenticatorAttachment         string   `json:"webAuthnPolicyPasswordlessAuthenticatorAttachment"`
	WebAuthnPolicyPasswordlessRequireResidentKey              string   `json:"webAuthnPolicyPasswordlessRequireResidentKey"`
	WebAuthnPolicyPasswordlessResidentKey                     string   `json:"webAuthnPolicyPasswordlessResidentKey"`
	WebAuthnPolicyPasswordlessUserVerificationRequirement     string   `json:"webAuthnPolicyPasswordlessUserVerificationRequirement"`
	WebAuthnPolicyPasswordlessCreateTimeout                   int      `json:"webAuthnPolicyPasswordlessCreateTimeout"`
	WebAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister  bool     `json:"webAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister"`
	WebAuthnPolicyPasswordlessAcceptableAaguids               []string `json:"webAuthnPolicyPasswordlessAcceptableAaguids"`
	WebAuthnPolicyPasswordlessExtraOrigins                    []string `json:"webAuthnPolicyPasswordlessExtraOrigins"`

	BrowserSecurityHeaders browserSecurityHeaders `json:"browserSecurityHeaders"`

	// SMTPServer is {} on both measured realms. A map rather than a struct
	// because P14 owns its contents and nothing has recorded a populated one;
	// an empty map marshals as {} where an empty struct would marshal as its
	// own key set.
	SMTPServer map[string]string `json:"smtpServer"`

	EventsEnabled               bool     `json:"eventsEnabled"`
	EventsListeners             []string `json:"eventsListeners"`
	EnabledEventTypes           []string `json:"enabledEventTypes"`
	AdminEventsEnabled          bool     `json:"adminEventsEnabled"`
	AdminEventsDetailsEnabled   bool     `json:"adminEventsDetailsEnabled"`
	InternationalizationEnabled bool     `json:"internationalizationEnabled"`
	BrowserFlow                 string   `json:"browserFlow"`
	RegistrationFlow            string   `json:"registrationFlow"`
	DirectGrantFlow             string   `json:"directGrantFlow"`
	ResetCredentialsFlow        string   `json:"resetCredentialsFlow"`
	ClientAuthenticationFlow    string   `json:"clientAuthenticationFlow"`
	DockerAuthenticationFlow    string   `json:"dockerAuthenticationFlow"`
	FirstBrokerLoginFlow        string   `json:"firstBrokerLoginFlow"`

	// Attributes is a Java map in hash order, which the conformance suite
	// normalises with Case.UnorderedKeys rather than reproducing - the same
	// retreat a client's attributes already take.
	Attributes map[string]string `json:"attributes"`

	UserManagedAccessAllowed     bool `json:"userManagedAccessAllowed"`
	OrganizationsEnabled         bool `json:"organizationsEnabled"`
	VerifiableCredentialsEnabled bool `json:"verifiableCredentialsEnabled"`
	AdminPermissionsEnabled      bool `json:"adminPermissionsEnabled"`
	ScimAPIEnabled               bool `json:"scimApiEnabled"`

	ClientProfiles clientProfiles `json:"clientProfiles"`
	ClientPolicies clientPolicies `json:"clientPolicies"`
}

// browserSecurityHeaders is a struct rather than a map because its measured key
// order is not alphabetical and Go sorts map keys. Seven keys, fixed set.
type browserSecurityHeaders struct {
	ContentSecurityPolicyReportOnly string `json:"contentSecurityPolicyReportOnly"`
	XContentTypeOptions             string `json:"xContentTypeOptions"`
	ReferrerPolicy                  string `json:"referrerPolicy"`
	XRobotsTag                      string `json:"xRobotsTag"`
	XFrameOptions                   string `json:"xFrameOptions"`
	ContentSecurityPolicy           string `json:"contentSecurityPolicy"`
	StrictTransportSecurity         string `json:"strictTransportSecurity"`
}

// clientProfiles and clientPolicies are the two one-key objects at the end of
// the body. Their contents are P4's cut C; the empty arrays are what a realm
// with none was measured carrying, and `[]` is exactly what omitempty drops, so
// neither field has it.
type clientProfiles struct {
	Profiles []clientProfile `json:"profiles"`
}

type clientPolicies struct {
	Policies []clientPolicy `json:"policies"`
}

// clientProfile and clientPolicy are placeholders: no realm measured so far
// carries one, so their fields are not known. Declaring them empty keeps the
// two arrays typed without inventing a shape.
type clientProfile struct{}

type clientPolicy struct{}

// realmBriefRepresentation is what the listing sends under
// briefRepresentation=true, to a caller that may view the realm. Three keys,
// five when the display names are set.
type realmBriefRepresentation struct {
	ID              string  `json:"id"`
	Realm           string  `json:"realm"`
	DisplayName     *string `json:"displayName,omitempty"`
	DisplayNameHTML *string `json:"displayNameHtml,omitempty"`
	Enabled         bool    `json:"enabled"`
}

// realmReducedRepresentation is what GET /admin/realms/{realm} sends to a
// caller holding an admin role other than view-realm or manage-realm. Four keys
// for sixteen of the admin roles, five for view-users and manage-users.
//
// **It is a 200, not a 403.** A weaker caller gets a shorter body, which is the
// same retreat the available role listings make and is easily mistaken for a
// bug.
//
// RegistrationEmailAsUsername is a pointer because its presence is the whole
// difference between the two shapes and its measured value is false, which
// omitempty would drop on the shape that carries it.
//
// SupportedLocales is here and **not** on the full representation: the 104-key
// body has no such key when internationalization is off, and this one sends [].
type realmReducedRepresentation struct {
	Realm                       string   `json:"realm"`
	DisplayName                 *string  `json:"displayName,omitempty"`
	DisplayNameHTML             *string  `json:"displayNameHtml,omitempty"`
	RegistrationEmailAsUsername *bool    `json:"registrationEmailAsUsername,omitempty"`
	BruteForceProtected         bool     `json:"bruteForceProtected"`
	SupportedLocales            []string `json:"supportedLocales"`
	OrganizationsEnabled        bool     `json:"organizationsEnabled"`
}

// realmNarrowRepresentation is a listing entry for a caller that may not view
// the realm: one key, and briefRepresentation does nothing to it - absent and
// true were measured giving byte-identical bodies. It is narrower than the
// reduced single read of the same realm by the same caller, which is the fifth
// shape of one resource.
type realmNarrowRepresentation struct {
	Realm string `json:"realm"`
}

// masterRealmName is the one realm whose defaults differ, and the one that
// cannot be deleted.
const masterRealmName = "master"

// defaultRealmRepresentation is what a realm created through
// POST /admin/realms was measured carrying, transcribed from a recording.
//
// It is a function rather than a package variable because it hands out maps and
// slices: a shared variable would let one request's PUT edit the defaults every
// other realm is read through.
//
// **master differs in three ways and they are named here rather than patched by
// the caller**: two display names it alone carries, and two attributes it alone
// lacks. Its accessTokenLifespan of 60 against a created realm's 300 is the
// fourth, and it is not here - that field is owned by the realm row and
// overwritten on read, so putting it in the defaults would be a second truth.
func defaultRealmRepresentation(name string) realmRepresentation {
	rep := realmRepresentation{
		DefaultSignatureAlgorithm:           "RS256",
		AccessTokenLifespan:                 300,
		AccessTokenLifespanForImplicitFlow:  900,
		SSOSessionIdleTimeout:               1800,
		SSOSessionMaxLifespan:               36000,
		OfflineSessionIdleTimeout:           2592000,
		OfflineSessionMaxLifespan:           5184000,
		AccessCodeLifespan:                  60,
		AccessCodeLifespanUserAction:        300,
		AccessCodeLifespanLogin:             1800,
		ActionTokenGeneratedByAdminLifespan: 43200,
		ActionTokenGeneratedByUserLifespan:  300,
		OAuth2DeviceCodeLifespan:            600,
		OAuth2DevicePollingInterval:         5,
		SSLRequired:                         "external",
		LoginWithEmailAllowed:               true,
		BruteForceStrategy:                  "MULTIPLE",
		MaxFailureWaitSeconds:               900,
		MinimumQuickLoginWaitSeconds:        60,
		WaitIncrementSeconds:                60,
		QuickLoginCheckMilliSeconds:         1000,
		MaxDeltaTimeSeconds:                 43200,
		FailureFactor:                       30,
		RequiredCredentials:                 []string{"password"},
		OTPPolicyType:                       "totp",
		OTPPolicyAlgorithm:                  "HmacSHA1",
		OTPPolicyDigits:                     6,
		OTPPolicyLookAheadWindow:            1,
		OTPPolicyPeriod:                     30,
		OTPSupportedApplications: []string{
			"totpAppFreeOTPName", "totpAppGoogleName", "totpAppMicrosoftAuthenticatorName",
		},
		WebAuthnPolicyRPEntityName:                                "keycloak",
		WebAuthnPolicySignatureAlgorithms:                         []string{"ES256", "RS256"},
		WebAuthnPolicyAttestationConveyancePreference:             notSpecified,
		WebAuthnPolicyAuthenticatorAttachment:                     notSpecified,
		WebAuthnPolicyRequireResidentKey:                          notSpecified,
		WebAuthnPolicyResidentKey:                                 notSpecified,
		WebAuthnPolicyUserVerificationRequirement:                 notSpecified,
		WebAuthnPolicyAcceptableAaguids:                           []string{},
		WebAuthnPolicyExtraOrigins:                                []string{},
		WebAuthnPolicyPasswordlessRPEntityName:                    "keycloak",
		WebAuthnPolicyPasswordlessSignatureAlgorithms:             []string{"ES256", "RS256"},
		WebAuthnPolicyPasswordlessAttestationConveyancePreference: notSpecified,
		WebAuthnPolicyPasswordlessAuthenticatorAttachment:         notSpecified,
		WebAuthnPolicyPasswordlessRequireResidentKey:              notSpecified,
		// The passwordless pair are the two that are not "not specified".
		WebAuthnPolicyPasswordlessResidentKey:                 "required",
		WebAuthnPolicyPasswordlessUserVerificationRequirement: "required",
		WebAuthnPolicyPasswordlessAcceptableAaguids:           []string{},
		WebAuthnPolicyPasswordlessExtraOrigins:                []string{},
		BrowserSecurityHeaders: browserSecurityHeaders{
			XContentTypeOptions:     "nosniff",
			ReferrerPolicy:          "no-referrer",
			XRobotsTag:              "none",
			XFrameOptions:           "SAMEORIGIN",
			ContentSecurityPolicy:   "frame-src 'self'; frame-ancestors 'self'; object-src 'none';",
			StrictTransportSecurity: "max-age=31536000; includeSubDomains",
		},
		SMTPServer:               map[string]string{},
		EventsListeners:          []string{"jboss-logging"},
		EnabledEventTypes:        []string{},
		BrowserFlow:              "browser",
		RegistrationFlow:         "registration",
		DirectGrantFlow:          "direct grant",
		ResetCredentialsFlow:     "reset credentials",
		ClientAuthenticationFlow: "clients",
		DockerAuthenticationFlow: "docker auth",
		FirstBrokerLoginFlow:     "first broker login",
		Attributes:               defaultRealmAttributes(name),
		ClientProfiles:           clientProfiles{Profiles: []clientProfile{}},
		ClientPolicies:           clientPolicies{Policies: []clientPolicy{}},
	}
	if name == masterRealmName {
		rep.DisplayName = ptr("Keycloak")
		rep.DisplayNameHTML = ptr(`<div class="kc-logo-text"><span>Keycloak</span></div>`)
	}
	return rep
}

// notSpecified is the literal WebAuthn policies carry, with the space. Nine of
// the twelve are this string.
const notSpecified = "not specified"

// defaultRealmAttributes is the realm's attribute map as measured. A created
// realm carries eight keys and master carries six: the two oauth2Device ones
// are absent from master although the top-level integers of the same names are
// present on both. Duplicated state that disagrees between two realms of one
// version, reproduced because it is observable.
func defaultRealmAttributes(name string) map[string]string {
	attrs := map[string]string{
		"cibaBackchannelTokenDeliveryMode": "poll",
		"cibaExpiresIn":                    "120",
		"cibaAuthRequestedUserHint":        "login_hint",
		"cibaInterval":                     "5",
		"parRequestUriLifespan":            "60",
		"realmReusableOtpCode":             "false",
	}
	if name != masterRealmName {
		attrs["oauth2DeviceCodeLifespan"] = "600"
		attrs["oauth2DevicePollingInterval"] = "5"
	}
	return attrs
}

// derivedRealmAttributes are the seven a PUT re-adds after replacing the map.
// Measured: a realm created with {"a":"1","b":"2"} answered a subsequent
// PUT {"attributes":{"c":"3"}} with c and these seven, having dropped a, b
// **and realmReusableOtpCode** - so the result is neither what was sent nor
// what was there, and this list is the difference.
var derivedRealmAttributes = []string{
	"cibaBackchannelTokenDeliveryMode",
	"cibaExpiresIn",
	"cibaAuthRequestedUserHint",
	"cibaInterval",
	"parRequestUriLifespan",
	"oauth2DeviceCodeLifespan",
	"oauth2DevicePollingInterval",
}

// ptr is the one-liner the pointer fields above need at their call sites.
func ptr[T any](v T) *T { return &v }
