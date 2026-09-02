// Code transcribed from a live Keycloak 26.7.1 on 2026-09-02. Do not hand-edit
// a value here without re-measuring it; the conformance goldens are what check
// this file, and a typo in a helpText is invisible to every other test.
//
// The measurement is recorded in
// docs/superpowers/plans/2026-09-02-p9-provider-catalogue.md, section 1.

package model

// identityProviderCatalogue is what
// `GET /admin/realms/{realm}/identity-provider/providers/{provider_id}` serves,
// for all seventeen registered providers.
//
// **Eleven of the seventeen declare no properties at all**, `oidc` and `saml`
// among them, so this endpoint serves a provider's *extra* configuration and
// not its whole surface. The biggest body is `google` at 2386 bytes and six
// properties; the whole table is 5816 bytes of JSON.
//
// Every entry's HelpText is the empty string and every ConfigMetadata is empty,
// on all seventeen - which is why neither is a field here and both are constants
// in the serialiser.
var identityProviderCatalogue = map[string]IdentityProviderCatalogueEntry{
	"kubernetes": {
		Name: "Kubernetes",
	},
	"jwt-authorization-grant": {
		Name: "JWT Authorization Grant",
	},
	"saml": {
		Name: "SAML v2.0",
	},
	"oauth2": {
		Name: "OAuth v2",
	},
	"oidc": {
		Name: "OpenID Connect v1.0",
	},
	"keycloak-oidc": {
		Name: "Keycloak OpenID Connect",
	},
	"linkedin-openid-connect": {
		Name: "LinkedIn",
	},
	"twitter": {
		Name: "Twitter",
	},
	"github": {
		Name: "GitHub",
		Properties: []ProviderProperty{
			{
				Name:     "baseUrl",
				Label:    "Base URL",
				HelpText: "Override the default Base URL for this identity provider.",
				Type:     "String",
			},
			{
				Name:     "apiUrl",
				Label:    "API URL",
				HelpText: "Override the default API URL for this identity provider.",
				Type:     "String",
			},
			{
				Name:         "githubJsonFormat",
				Label:        "JSON Format",
				HelpText:     "Enable to receive JSON format responses from GitHub. This is also required to automatically refresh access tokens retrieved from GitHub.",
				Type:         "boolean",
				DefaultValue: false,
			},
		},
	},
	"openshift-v4": {
		Name: "Openshift v4",
		Properties: []ProviderProperty{
			{
				Name:     "baseUrl",
				Label:    "Base URL",
				HelpText: "Override the default Base URL for this identity provider.",
				Type:     "String",
			},
		},
	},
	"facebook": {
		Name: "Facebook",
		Properties: []ProviderProperty{
			{
				Name:     "fetchedFields",
				Label:    "Additional user's profile fields",
				HelpText: "Provide additional fields which would be fetched using the profile request. This will be appended to the default set of 'id,name,email,first_name,last_name'.",
				Type:     "String",
			},
		},
	},
	"google": {
		Name: "Google",
		Properties: []ProviderProperty{
			{
				Name:     "prompt",
				Label:    "Prompt",
				HelpText: "Set 'prompt' query parameter when logging in with Google. The allowed values are 'none', 'consent' and 'select_account'. If no value is specified and the user has not previously authorized access, then the user is shown a consent screen.",
				Type:     "String",
			},
			{
				Name:     "hostedDomain",
				Label:    "Hosted Domain",
				HelpText: "Set 'hd' query parameter when logging in with Google. Google will list accounts only for this domain. Keycloak validates that the returned identity token has a claim for this domain. When '*' is entered, any hosted account can be used. Comma ',' separated list of domains is supported.",
				Type:     "String",
			},
			{
				Name:     "userIp",
				Label:    "Use userIp param",
				HelpText: "Set 'userIp' query parameter when invoking on Google's User Info service.  This will use the user's ip address.  Useful if Google is throttling access to the User Info service.",
				Type:     "boolean",
			},
			{
				Name:     "offlineAccess",
				Label:    "Request refresh token",
				HelpText: "Set 'access_type' query parameter to 'offline' when redirecting to google authorization endpoint, to get a refresh token back. Useful if planning to use Token Exchange to retrieve Google token to access Google APIs when the user is not at the browser.",
				Type:     "boolean",
			},
			{
				Name:     "jwtAuthorizationGrantEnabled",
				Label:    "JWT Authorization Grant",
				HelpText: "Enable the Google identity provider to act as a trust provider to validate authorization grant JWT assertions (Google ID Token) according to RFC 7523, except for the audience claim that must contain the client id of the configured client",
				Type:     "boolean",
			},
			{
				Name:         "jwtAuthorizationGrantMaxAllowedAssertionExpiration",
				Label:        "Max allowed assertion expiration",
				HelpText:     "This property is used only for JWT Authorization Grant to set the max accepted duration limit for the assertion. Note that the Google ID Token expires after 1 hour, so this property can be used to limit the time during which the assertion can be used.",
				Type:         "Number",
				DefaultValue: "3600",
			},
		},
	},
	"gitlab": {
		Name: "GitLab",
	},
	"microsoft": {
		Name: "Microsoft",
		Properties: []ProviderProperty{
			{
				Name:     "prompt",
				Label:    "Prompt",
				HelpText: "Indicates the type of user interaction that is required. The only valid values at this time are login, none, consent, and select_account.",
				Type:     "String",
			},
			{
				Name:     "tenantId",
				Label:    "Tenant ID",
				HelpText: "Uses single-tenant auth endpoints when specified, uses 'common' multi-tenant endpoints otherwise.",
				Type:     "String",
			},
		},
	},
	"bitbucket": {
		Name: "BitBucket",
	},
	"paypal": {
		Name: "PayPal",
		Properties: []ProviderProperty{
			{
				Name:     "sandbox",
				Label:    "Target Sandbox",
				HelpText: "Target PayPal's sandbox environment",
				Type:     "boolean",
			},
		},
	},
	"stackoverflow": {
		Name: "StackOverflow",
		Properties: []ProviderProperty{
			{
				Name:     "key",
				Label:    "Key",
				HelpText: "The Key obtained from Stack Overflow client registration.",
				Type:     "String",
			},
		},
	},
}

// identityProviderMapperCatalogue is every distinct mapper type the fifteen
// answering providers offer between them - twenty-three, 21990 bytes of JSON as
// one object, transcribed from thirteen measured bodies plus the two providers
// that need config before an instance can exist.
//
// An entry is byte-identical wherever it appears: the same mapper type served
// from `oidc` and from `saml` is the same object, which is what lets this be a
// union rather than one table per provider.
var identityProviderMapperCatalogue = map[string]IdentityProviderMapperType{
	"facebook-user-attribute-mapper": {
		Name:     "Attribute Importer",
		Category: "Attribute Importer",
		HelpText: "Import user profile information if it exists in Social provider JSON data into the specified user attribute.",
		Properties: []ProviderProperty{
			{
				Name:     "jsonField",
				Label:    "Social Profile JSON Field Path",
				HelpText: "Path of field in Social provider User Profile JSON data to get value from. You can use dot notation for nesting and square brackets for array index. Eg. 'contact.address[0].country'.",
				Type:     "String",
			},
			{
				Name:     "userAttribute",
				Label:    "User Attribute Name",
				HelpText: "User attribute name to store information into.",
				Type:     "UserProfileAttributeList",
			},
		},
	},
	"github-user-attribute-mapper": {
		Name:     "Attribute Importer",
		Category: "Attribute Importer",
		HelpText: "Import user profile information if it exists in Social provider JSON data into the specified user attribute.",
		Properties: []ProviderProperty{
			{
				Name:     "jsonField",
				Label:    "Social Profile JSON Field Path",
				HelpText: "Path of field in Social provider User Profile JSON data to get value from. You can use dot notation for nesting and square brackets for array index. Eg. 'contact.address[0].country'.",
				Type:     "String",
			},
			{
				Name:     "userAttribute",
				Label:    "User Attribute Name",
				HelpText: "User attribute name to store information into.",
				Type:     "UserProfileAttributeList",
			},
		},
	},
	"google-user-attribute-mapper": {
		Name:     "Attribute Importer",
		Category: "Attribute Importer",
		HelpText: "Import user profile information if it exists in Social provider JSON data into the specified user attribute.",
		Properties: []ProviderProperty{
			{
				Name:     "jsonField",
				Label:    "Social Profile JSON Field Path",
				HelpText: "Path of field in Social provider User Profile JSON data to get value from. You can use dot notation for nesting and square brackets for array index. Eg. 'contact.address[0].country'.",
				Type:     "String",
			},
			{
				Name:     "userAttribute",
				Label:    "User Attribute Name",
				HelpText: "User attribute name to store information into.",
				Type:     "UserProfileAttributeList",
			},
		},
	},
	"hardcoded-attribute-idp-mapper": {
		Name:     "Hardcoded Attribute",
		Category: "Attribute Importer",
		HelpText: "When user is imported from provider, hardcode a value to a specific user attribute.",
		Properties: []ProviderProperty{
			{
				Name:     "attribute",
				Label:    "User Attribute",
				HelpText: "Name of user attribute you want to hardcode",
				Type:     "UserProfileAttributeList",
			},
			{
				Name:     "attribute.value",
				Label:    "User Attribute Value",
				HelpText: "Value you want to hardcode",
				Type:     "String",
			},
		},
	},
	"hardcoded-user-session-attribute-idp-mapper": {
		Name:     "Hardcoded User Session Attribute",
		Category: "Attribute Importer",
		HelpText: "When user is imported from provider, hardcode a value to a specific user session attribute.",
		Properties: []ProviderProperty{
			{
				Name:     "attribute",
				Label:    "User Session Attribute",
				HelpText: "Name of user session attribute you want to hardcode",
				Type:     "String",
			},
			{
				Name:     "attribute.value",
				Label:    "User Session Attribute Value",
				HelpText: "Value you want to hardcode",
				Type:     "String",
			},
		},
	},
	"keycloak-oidc-role-to-role-idp-mapper": {
		Name:     "External Role to Role",
		Category: "Role Importer",
		HelpText: "Looks for an external role in a keycloak access token.  If external role exists, grant the user the specified realm or client role.",
		Properties: []ProviderProperty{
			{
				Name:     "external.role",
				Label:    "External role",
				HelpText: "External role to check for.  To reference a client role the syntax is clientname.clientrole, i.e. myclient.myrole",
				Type:     "String",
			},
			{
				Name:     "role",
				Label:    "Role",
				HelpText: "Role to grant to user if external role is present.  Click 'Select Role' button to browse roles, or just type it in the textbox.  To reference a client role the syntax is clientname.clientrole, i.e. myclient.myrole",
				Type:     "Role",
			},
		},
	},
	"microsoft-user-attribute-mapper": {
		Name:     "Attribute Importer",
		Category: "Attribute Importer",
		HelpText: "Import user profile information if it exists in Social provider JSON data into the specified user attribute.",
		Properties: []ProviderProperty{
			{
				Name:     "jsonField",
				Label:    "Social Profile JSON Field Path",
				HelpText: "Path of field in Social provider User Profile JSON data to get value from. You can use dot notation for nesting and square brackets for array index. Eg. 'contact.address[0].country'.",
				Type:     "String",
			},
			{
				Name:     "userAttribute",
				Label:    "User Attribute Name",
				HelpText: "User attribute name to store information into.",
				Type:     "UserProfileAttributeList",
			},
		},
	},
	"oidc-advanced-group-idp-mapper": {
		Name:     "Advanced Claim to Group",
		Category: "Group Importer",
		HelpText: "If all claims exists, assign the user to the specified group.",
		Properties: []ProviderProperty{
			{
				Name:     "claims",
				Label:    "Claims",
				HelpText: "Name and value of the claims to search for in token. You can reference nested claims using a '.', i.e. 'address.locality'. To use dot (.) literally, escape it with backslash (\\.)",
				Type:     "Map",
			},
			{
				Name:     "are.claim.values.regex",
				Label:    "Regex Claim Values",
				HelpText: "If enabled claim values are interpreted as regular expressions.",
				Type:     "boolean",
			},
			{
				Name:     "group",
				Label:    "Group",
				HelpText: "Group to assign the user to if claim is present.",
				Type:     "Group",
			},
		},
	},
	"oidc-advanced-role-idp-mapper": {
		Name:     "Advanced Claim to Role",
		Category: "Role Importer",
		HelpText: "If all claims exists, grant the user the specified realm or client role.",
		Properties: []ProviderProperty{
			{
				Name:     "claims",
				Label:    "Claims",
				HelpText: "Name and value of the claims to search for in token. You can reference nested claims using a '.', i.e. 'address.locality'. To use dot (.) literally, escape it with backslash (\\.)",
				Type:     "Map",
			},
			{
				Name:     "are.claim.values.regex",
				Label:    "Regex Claim Values",
				HelpText: "If enabled claim values are interpreted as regular expressions.",
				Type:     "boolean",
			},
			{
				Name:     "role",
				Label:    "Role",
				HelpText: "Role to grant to user if claim is present. Click 'Select Role' button to browse roles, or just type it in the textbox. To reference a client role the syntax is clientname.clientrole, i.e. myclient.myrole",
				Type:     "Role",
			},
		},
	},
	"oidc-hardcoded-group-idp-mapper": {
		Name:     "Hardcoded Group",
		Category: "Group Importer",
		HelpText: "Assign the user to the specified group.",
		Properties: []ProviderProperty{
			{
				Name:     "group",
				Label:    "Group",
				HelpText: "Group to assign the user.",
				Type:     "Group",
			},
		},
	},
	"oidc-hardcoded-role-idp-mapper": {
		Name:     "Hardcoded Role",
		Category: "Role Importer",
		HelpText: "When user is imported from provider, hardcode a role mapping for it.",
		Properties: []ProviderProperty{
			{
				Name:     "role",
				Label:    "Role",
				HelpText: "Role to grant to user.  Click 'Select Role' button to browse roles, or just type it in the textbox.  To reference a client role the syntax is clientname.clientrole, i.e. myclient.myrole",
				Type:     "Role",
			},
		},
	},
	"oidc-role-idp-mapper": {
		Name:     "Claim to Role",
		Category: "Role Importer",
		HelpText: "If a claim exists, grant the user the specified realm or client role.",
		Properties: []ProviderProperty{
			{
				Name:     "claim",
				Label:    "Claim",
				HelpText: "Name of claim to search for in token. You can reference nested claims using a '.', i.e. 'address.locality'. To use dot (.) literally, escape it with backslash (\\.)",
				Type:     "String",
			},
			{
				Name:     "claim.value",
				Label:    "Claim Value",
				HelpText: "Value the claim must have.  If the claim is an array, then the value must be contained in the array.",
				Type:     "String",
			},
			{
				Name:     "role",
				Label:    "Role",
				HelpText: "Role to grant to user if claim is present.  Click 'Select Role' button to browse roles, or just type it in the textbox.  To reference a client role the syntax is clientname.clientrole, i.e. myclient.myrole",
				Type:     "Role",
			},
		},
	},
	"oidc-user-attribute-idp-mapper": {
		Name:     "Attribute Importer",
		Category: "Attribute Importer",
		HelpText: "Import declared claim if it exists in ID, access token or the claim set returned by the user profile endpoint into the specified user property or attribute.",
		Properties: []ProviderProperty{
			{
				Name:     "claim",
				Label:    "Claim",
				HelpText: "Name of claim to search for in token. You can reference nested claims using a '.', i.e. 'address.locality'. To use dot (.) literally, escape it with backslash (\\.)",
				Type:     "String",
			},
			{
				Name:     "user.attribute",
				Label:    "User Attribute Name",
				HelpText: "User attribute name to store claim.  Use email, lastName, and firstName to map to those predefined user properties.",
				Type:     "UserProfileAttributeList",
			},
			{
				Name:         "allow.nullable.property",
				Label:        "Allow Nullable Property",
				HelpText:     "If true, the property will be set to null when the claim is empty.",
				Type:         "boolean",
				DefaultValue: "false",
			},
		},
	},
	"oidc-user-session-note-idp-mapper": {
		Name:     "User Session Note Mapper",
		Category: "User Session",
		HelpText: "Add every matching claim to the user session note. This can be used together for instance with the 'User Session Note' protocol mapper configured for your client scope or client, so that claims for 3rd party IDPs would be available in the access token sent to your client application.",
		Properties: []ProviderProperty{
			{
				Name:     "claims",
				Label:    "Claims",
				HelpText: "Names and values of the claims to search for in the token. You can reference nested claims using a '.', i.e. 'address.locality'. To use dot (.) literally, escape it with backslash (\\.)",
				Type:     "Map",
			},
			{
				Name:     "are.claim.values.regex",
				Label:    "Regex Claim Values",
				HelpText: "If enabled, claim values are interpreted as regular expressions.",
				Type:     "boolean",
			},
		},
	},
	"oidc-username-idp-mapper": {
		Name:     "Username Template Importer",
		Category: "Preprocessor",
		HelpText: "Format the username to import.",
		Properties: []ProviderProperty{
			{
				Name:         "template",
				Label:        "Template",
				HelpText:     "Template to use to format the username to import.  Substitutions are enclosed in ${}.  For example: '${ALIAS}.${CLAIM.sub}'.  ALIAS is the provider alias.  CLAIM.<NAME> references an ID or Access token claim. \nThe substitution can be converted to upper or lower case by appending |uppercase or |lowercase to the substituted value, e.g. '${CLAIM.sub | lowercase}",
				Type:         "String",
				DefaultValue: "${ALIAS}.${CLAIM.preferred_username}",
			},
			{
				Name:         "target",
				Label:        "Target",
				HelpText:     "Destination field for the mapper. LOCAL (default) means that the changes are applied to the username stored in local database upon user import. BROKER_ID and BROKER_USERNAME means that the changes are stored into the ID or username used for federation user lookup, respectively.",
				Type:         "List",
				DefaultValue: "LOCAL",
				Options:      []string{"LOCAL", "BROKER_ID", "BROKER_USERNAME"},
			},
		},
	},
	"paypal-user-attribute-mapper": {
		Name:     "Attribute Importer",
		Category: "Attribute Importer",
		HelpText: "Import user profile information if it exists in Social provider JSON data into the specified user attribute.",
		Properties: []ProviderProperty{
			{
				Name:     "jsonField",
				Label:    "Social Profile JSON Field Path",
				HelpText: "Path of field in Social provider User Profile JSON data to get value from. You can use dot notation for nesting and square brackets for array index. Eg. 'contact.address[0].country'.",
				Type:     "String",
			},
			{
				Name:     "userAttribute",
				Label:    "User Attribute Name",
				HelpText: "User attribute name to store information into.",
				Type:     "UserProfileAttributeList",
			},
		},
	},
	"saml-advanced-group-idp-mapper": {
		Name:     "Advanced Attribute to Group",
		Category: "Group Importer",
		HelpText: "If all attributes exists, assign the user to the specified group.",
		Properties: []ProviderProperty{
			{
				Name:     "attributes",
				Label:    "Attributes",
				HelpText: "Name and value of the attributes to search for in token. You can reference nested attributes using a '.', i.e. 'address.locality'. To use dot (.) literally, escape it with backslash (\\.)",
				Type:     "Map",
			},
			{
				Name:     "are.attribute.values.regex",
				Label:    "Regex Attribute Values",
				HelpText: "If enabled attribute values are interpreted as regular expressions.",
				Type:     "boolean",
			},
			{
				Name:     "group",
				Label:    "Group",
				HelpText: "Group to assign the user to if attribute is present.",
				Type:     "Group",
			},
		},
	},
	"saml-advanced-role-idp-mapper": {
		Name:     "Advanced Attribute to Role",
		Category: "Role Importer",
		HelpText: "If the set of attributes exists and can be matched, grant the user the specified realm or client role.",
		Properties: []ProviderProperty{
			{
				Name:     "attributes",
				Label:    "Attributes",
				HelpText: "Name and (regex) value of the attributes to search for in token.  The configured name of an attribute is searched in SAML attribute name and attribute friendly name fields. Every given attribute description must be met to set the role. If the attribute is an array, then the value must be contained in the array. If an attribute can be found several times, then one match is sufficient.",
				Type:     "Map",
			},
			{
				Name:     "are.attribute.values.regex",
				Label:    "Regex Attribute Values",
				HelpText: "If enabled attribute values are interpreted as regular expressions.",
				Type:     "boolean",
			},
			{
				Name:     "role",
				Label:    "Role",
				HelpText: "Role to grant to user if all attributes are present. Click 'Select Role' button to browse roles, or just type it in the textbox. To reference a client role the syntax is clientname.clientrole, i.e. myclient.myrole",
				Type:     "Role",
			},
		},
	},
	"saml-role-idp-mapper": {
		Name:     "SAML Attribute to Role",
		Category: "Role Mapper",
		HelpText: "If an attribute exists, grant the user the specified realm or client role.",
		Properties: []ProviderProperty{
			{
				Name:     "attribute.name",
				Label:    "Attribute Name",
				HelpText: "Name of attribute to search for in assertion.  You can leave this blank and specify a friendly name instead.",
				Type:     "String",
			},
			{
				Name:     "attribute.friendly.name",
				Label:    "Friendly Name",
				HelpText: "Friendly name of attribute to search for in assertion.  You can leave this blank and specify a name instead.",
				Type:     "String",
			},
			{
				Name:     "attribute.value",
				Label:    "Attribute Value",
				HelpText: "Value the attribute must have.  If the attribute is a list, then the value must be contained in the list.",
				Type:     "String",
			},
			{
				Name:     "role",
				Label:    "Role",
				HelpText: "Role to grant to user.  Click 'Select Role' button to browse roles, or just type it in the textbox.  To reference a client role the syntax is clientname.clientrole, i.e. myclient.myrole",
				Type:     "Role",
			},
		},
	},
	"saml-user-attribute-idp-mapper": {
		Name:     "Attribute Importer",
		Category: "Attribute Importer",
		HelpText: "Import declared saml attribute if it exists in assertion into the specified user property or attribute.",
		Properties: []ProviderProperty{
			{
				Name:     "attribute.name",
				Label:    "Attribute Name",
				HelpText: "Name of attribute to search for in assertion.  You can leave this blank and specify a friendly name instead.",
				Type:     "String",
			},
			{
				Name:     "attribute.friendly.name",
				Label:    "Friendly Name",
				HelpText: "Friendly name of attribute to search for in assertion.  You can leave this blank and specify a name instead.",
				Type:     "String",
			},
			{
				Name:         "attribute.name.format",
				Label:        "Name Format",
				HelpText:     "Name format of attribute to specify in the RequestedAttribute element. Default to basic format.",
				Type:         "List",
				DefaultValue: "ATTRIBUTE_FORMAT_BASIC",
				Options:      []string{"ATTRIBUTE_FORMAT_BASIC", "ATTRIBUTE_FORMAT_URI", "ATTRIBUTE_FORMAT_UNSPECIFIED"},
			},
			{
				Name:     "user.attribute",
				Label:    "User Attribute Name",
				HelpText: "User attribute name to store saml attribute.  Use email, lastName, and firstName to map to those predefined user properties.",
				Type:     "UserProfileAttributeList",
			},
			{
				Name:         "allow.nullable.property",
				Label:        "Allow Nullable Property",
				HelpText:     "If true, the property will be set to null when the claim is empty.",
				Type:         "boolean",
				DefaultValue: "false",
			},
		},
	},
	"saml-username-idp-mapper": {
		Name:     "Username Template Importer",
		Category: "Preprocessor",
		HelpText: "Format the username to import.",
		Properties: []ProviderProperty{
			{
				Name:         "template",
				Label:        "Template",
				HelpText:     "Template to use to format the username to import.  Substitutions are enclosed in ${}.  For example: '${ALIAS}.${NAMEID}'.  ALIAS is the provider alias.  NAMEID is that SAML name id assertion.  ATTRIBUTE.<NAME> references a SAML attribute where name is the attribute name or friendly name. \nThe substitution can be converted to upper or lower case by appending |uppercase or |lowercase to the substituted value, e.g. '${NAMEID | lowercase} \nLocal part of email can be extracted by appending |localpart to the substituted value, e.g. ${ATTRIBUTE.email | localpart}. If \"@\" is not part of the string, this conversion leaves the substitution untouched.",
				Type:         "String",
				DefaultValue: "${ALIAS}.${NAMEID}",
			},
			{
				Name:         "target",
				Label:        "Target",
				HelpText:     "Destination field for the mapper. LOCAL (default) means that the changes are applied to the username stored in local database upon user import. BROKER_ID and BROKER_USERNAME means that the changes are stored into the ID or username used for federation user lookup, respectively.",
				Type:         "List",
				DefaultValue: "LOCAL",
				Options:      []string{"LOCAL", "BROKER_ID", "BROKER_USERNAME"},
			},
		},
	},
	"saml-xpath-attribute-idp-mapper": {
		Name:     "XPath Attribute Importer",
		Category: "Attribute Importer",
		HelpText: "Extract text of a saml attribute via XPath expression and import into the specified user property or attribute.",
		Properties: []ProviderProperty{
			{
				Name:     "attribute.xpath",
				Label:    "Attribute XPath",
				HelpText: "XPath expression to search for. All attributes are surrounded with a <root> element. Given prefixes and namespaces are preserved. Example: <root><myPrefix:Person xmlns:myPrefix=\"http://my.namespace/schema\"><myPrefix:FirstName>John</myPrefix:FirstName>...</myPrefix:Person></root> or <root>Some attribute value of anyType</root>",
				Type:     "String",
			},
			{
				Name:     "attribute.name",
				Label:    "Attribute Name",
				HelpText: "Name of attribute to search for in assertion and apply XPath. You can leave this blank to try to apply XPath to all attributes or specify a friendly name instead.",
				Type:     "String",
			},
			{
				Name:     "attribute.friendly.name",
				Label:    "Friendly Name",
				HelpText: "Friendly name of attribute to search for in assertion. You can leave this blank to try to apply XPath to all attributes or specify a name instead.",
				Type:     "String",
			},
			{
				Name:     "user.attribute",
				Label:    "User Attribute Name",
				HelpText: "User attribute name to store XPath value. Use email, firstName, and lastName for e-mail, first and last name, respectively.",
				Type:     "UserProfileAttributeList",
			},
		},
	},
	"stackoverflow-user-attribute-mapper": {
		Name:     "Attribute Importer",
		Category: "Attribute Importer",
		HelpText: "Import user profile information if it exists in Social provider JSON data into the specified user attribute.",
		Properties: []ProviderProperty{
			{
				Name:     "jsonField",
				Label:    "Social Profile JSON Field Path",
				HelpText: "Path of field in Social provider User Profile JSON data to get value from. You can use dot notation for nesting and square brackets for array index. Eg. 'contact.address[0].country'.",
				Type:     "String",
			},
			{
				Name:     "userAttribute",
				Label:    "User Attribute Name",
				HelpText: "User attribute name to store information into.",
				Type:     "UserProfileAttributeList",
			},
		},
	},
}

// identityProviderMapperIDs is the mapper set each provider offers, **in the
// order the server sent it**.
//
// The order is not alphabetical and it is not insertion order either: the body
// is a Java HashMap keyed on the mapper id, and all thirteen measured key sets
// are bucket-monotone at capacity 16. javamap.KeyOrder places eight of the
// thirteen exactly and the five it misses hold six colliding pairs between them,
// which is the tie-break gap that package documents rather than a wrong bucket.
//
// So the order is **stored rather than computed**. It was byte-identical across
// two container starts on all seventeen providers, which makes it a constant of
// the Keycloak version; computing it would mean guessing at six chains for no
// gain.
//
// **Two providers are absent on purpose, and their absence is the 500.**
// `linkedin-openid-connect` and `openshift-v4` answer `mapper-types` with the
// consult-the-log `unknown_error` on an instance that was created without
// complaint and reads back normally through every other route in the family. So
// an entry arriving here for either of them would turn a measured 500 into a
// served map, which is why the absent set is asserted rather than assumed - see
// TestTheProvidersWithNoMapperTypesAreTheTwoMeasured500s.
var identityProviderMapperIDs = map[string][]string{
	"kubernetes": {
		"hardcoded-user-session-attribute-idp-mapper",
		"oidc-hardcoded-role-idp-mapper",
		"oidc-hardcoded-group-idp-mapper",
		"hardcoded-attribute-idp-mapper",
	},
	"jwt-authorization-grant": {
		"hardcoded-user-session-attribute-idp-mapper",
		"oidc-hardcoded-role-idp-mapper",
		"oidc-hardcoded-group-idp-mapper",
		"hardcoded-attribute-idp-mapper",
	},
	"saml": {
		"saml-username-idp-mapper",
		"saml-advanced-role-idp-mapper",
		"saml-xpath-attribute-idp-mapper",
		"hardcoded-user-session-attribute-idp-mapper",
		"saml-user-attribute-idp-mapper",
		"oidc-hardcoded-role-idp-mapper",
		"oidc-hardcoded-group-idp-mapper",
		"saml-advanced-group-idp-mapper",
		"hardcoded-attribute-idp-mapper",
		"saml-role-idp-mapper",
	},
	"oauth2": {
		"hardcoded-user-session-attribute-idp-mapper",
		"oidc-hardcoded-role-idp-mapper",
		"oidc-hardcoded-group-idp-mapper",
		"hardcoded-attribute-idp-mapper",
	},
	"oidc": {
		"oidc-advanced-group-idp-mapper",
		"hardcoded-user-session-attribute-idp-mapper",
		"oidc-user-attribute-idp-mapper",
		"oidc-advanced-role-idp-mapper",
		"oidc-hardcoded-role-idp-mapper",
		"oidc-hardcoded-group-idp-mapper",
		"oidc-user-session-note-idp-mapper",
		"oidc-role-idp-mapper",
		"hardcoded-attribute-idp-mapper",
		"oidc-username-idp-mapper",
	},
	"keycloak-oidc": {
		"oidc-advanced-group-idp-mapper",
		"hardcoded-user-session-attribute-idp-mapper",
		"oidc-user-attribute-idp-mapper",
		"keycloak-oidc-role-to-role-idp-mapper",
		"oidc-advanced-role-idp-mapper",
		"oidc-hardcoded-role-idp-mapper",
		"oidc-hardcoded-group-idp-mapper",
		"oidc-user-session-note-idp-mapper",
		"oidc-role-idp-mapper",
		"hardcoded-attribute-idp-mapper",
		"oidc-username-idp-mapper",
	},
	"twitter": {
		"hardcoded-user-session-attribute-idp-mapper",
		"oidc-hardcoded-role-idp-mapper",
		"oidc-hardcoded-group-idp-mapper",
		"hardcoded-attribute-idp-mapper",
		"oidc-username-idp-mapper",
	},
	"github": {
		"github-user-attribute-mapper",
		"hardcoded-user-session-attribute-idp-mapper",
		"oidc-hardcoded-role-idp-mapper",
		"oidc-hardcoded-group-idp-mapper",
		"hardcoded-attribute-idp-mapper",
		"oidc-username-idp-mapper",
	},
	"facebook": {
		"hardcoded-user-session-attribute-idp-mapper",
		"oidc-hardcoded-role-idp-mapper",
		"facebook-user-attribute-mapper",
		"oidc-hardcoded-group-idp-mapper",
		"hardcoded-attribute-idp-mapper",
		"oidc-username-idp-mapper",
	},
	"google": {
		"hardcoded-user-session-attribute-idp-mapper",
		"oidc-hardcoded-role-idp-mapper",
		"oidc-hardcoded-group-idp-mapper",
		"google-user-attribute-mapper",
		"hardcoded-attribute-idp-mapper",
		"oidc-username-idp-mapper",
	},
	"gitlab": {
		"hardcoded-user-session-attribute-idp-mapper",
		"oidc-hardcoded-role-idp-mapper",
		"oidc-hardcoded-group-idp-mapper",
		"hardcoded-attribute-idp-mapper",
		"oidc-username-idp-mapper",
	},
	"microsoft": {
		"microsoft-user-attribute-mapper",
		"hardcoded-user-session-attribute-idp-mapper",
		"oidc-hardcoded-role-idp-mapper",
		"oidc-hardcoded-group-idp-mapper",
		"hardcoded-attribute-idp-mapper",
		"oidc-username-idp-mapper",
	},
	"bitbucket": {
		"hardcoded-user-session-attribute-idp-mapper",
		"oidc-hardcoded-role-idp-mapper",
		"oidc-hardcoded-group-idp-mapper",
		"hardcoded-attribute-idp-mapper",
		"oidc-username-idp-mapper",
	},
	"paypal": {
		"hardcoded-user-session-attribute-idp-mapper",
		"oidc-hardcoded-role-idp-mapper",
		"paypal-user-attribute-mapper",
		"oidc-hardcoded-group-idp-mapper",
		"hardcoded-attribute-idp-mapper",
		"oidc-username-idp-mapper",
	},
	"stackoverflow": {
		"stackoverflow-user-attribute-mapper",
		"hardcoded-user-session-attribute-idp-mapper",
		"oidc-hardcoded-role-idp-mapper",
		"oidc-hardcoded-group-idp-mapper",
		"hardcoded-attribute-idp-mapper",
		"oidc-username-idp-mapper",
	},
}
