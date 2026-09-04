// Code transcribed from a live Keycloak 26.7.1 on 2026-09-03. Do not hand-edit
// a value here without re-measuring it; the conformance goldens are what check
// this file, and a typo in a helpText is invisible to every other test.
//
// The measurement is recorded in
// docs/superpowers/plans/2026-09-03-small-chapters.md, sections 3.3 and 3.4.

package model

// componentSubTypes is what
// `GET /admin/realms/{realm}/components/{id}/sub-component-types?type=X`
// serves, for the five provider types that answer it non-empty.
//
// 33 entries, 168 properties, 47650 bytes, **byte-identical across three
// parent components, two realms and two container starts** - which is what
// makes a table right for it and lets the goldens assert the array in order
// rather than masking it.
//
// The other thirteen registered provider types answer `[]` and are in
// componentProviderRegistry below rather than here, because an empty entry
// list and an unregistered type are two different answers on `POST`.
var componentSubTypes = map[string][]ComponentTypeEntry{
	"org.keycloak.keys.KeyProvider": {
		{
			ID:       "rsa",
			HelpText: strptr("RSA signature key provider that can optionally generated a self-signed certificate"),
			Properties: []ProviderProperty{
				{Name: "priority", Label: "Priority", HelpText: "Priority for the provider", Type: "String", DefaultValue: "0"},
				{Name: "enabled", Label: "Enabled", HelpText: "Set if the keys are enabled", Type: "boolean", DefaultValue: "true"},
				{Name: "active", Label: "Active", HelpText: "Set if the keys can be used for signing", Type: "boolean", DefaultValue: "true"},
				{Name: "privateKey", Label: "Private RSA Key", HelpText: "Private RSA Key encoded in PEM format", Type: "File", Secret: true},
				{Name: "certificate", Label: "X509 Certificate", HelpText: "X509 Certificate encoded in PEM format", Type: "File"},
				{Name: "algorithm", Label: "Algorithm", HelpText: "Intended algorithm for the key", Type: "List", DefaultValue: "RS256", Options: []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}},
			},
		},
		{
			ID:       "rsa-generated",
			HelpText: strptr("Generates RSA signature keys and creates a self-signed certificate"),
			Properties: []ProviderProperty{
				{Name: "priority", Label: "Priority", HelpText: "Priority for the provider", Type: "String", DefaultValue: "0"},
				{Name: "enabled", Label: "Enabled", HelpText: "Set if the keys are enabled", Type: "boolean", DefaultValue: "true"},
				{Name: "active", Label: "Active", HelpText: "Set if the keys can be used for signing", Type: "boolean", DefaultValue: "true"},
				{Name: "keySize", Label: "Key size", HelpText: "Size for the generated keys", Type: "List", DefaultValue: 2048, Options: []string{"1024", "2048", "3072", "4096"}},
				{Name: "algorithm", Label: "Algorithm", HelpText: "Intended algorithm for the key", Type: "List", DefaultValue: "RS256", Options: []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}},
			},
		},
		{
			ID:       "java-keystore",
			HelpText: strptr("Loads keys from a Java keys file"),
			Properties: []ProviderProperty{
				{Name: "priority", Label: "Priority", HelpText: "Priority for the provider", Type: "String", DefaultValue: "0"},
				{Name: "enabled", Label: "Enabled", HelpText: "Set if the keys are enabled", Type: "boolean", DefaultValue: "true"},
				{Name: "active", Label: "Active", HelpText: "Set if the keys can be used for signing", Type: "boolean", DefaultValue: "true"},
				{Name: "algorithm", Label: "Algorithm", HelpText: "Intended algorithm for the key", Type: "List", DefaultValue: "RS256", Options: []string{"AES", "EdDSA", "ES256", "ES384", "ES512", "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "RSA1_5", "RSA-OAEP", "RSA-OAEP-256", "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"}},
				{Name: "keystore", Label: "Keystore", HelpText: "Path to the keystore file. The keystore should be located inside a folder named like the realm name inside\nthe main keystores directory (by default `data` directory under {project_name}'s installation folder). For a\nrealm called `test` the keystore file should located inside `${kc.home.dir}/data/test`. This way the keystore\nfile is isolated between different realms. If the path is relative, the file will be located from that folder.\n", Type: "String"},
				{Name: "keystorePassword", Label: "Keystore Password", HelpText: "Password for the keys", Type: "String", Secret: true},
				{Name: "keystoreType", Label: "Keystore Type", HelpText: "Keystore type. This parameter is not mandatory. If omitted, the type will be detected from keystore file or default keystore type will be used", Type: "List", DefaultValue: "JKS", Options: []string{"JKS", "PKCS12", "BCFKS"}},
				{Name: "keyAlias", Label: "Key Alias", HelpText: "Alias for the private key", Type: "String"},
				{Name: "keyPassword", Label: "Key Password", HelpText: "Password for the private key", Type: "String", Secret: true},
				{Name: "keyUse", Label: "Key use", HelpText: "Whether the key should be used for signing or encryption.", Type: "List", DefaultValue: "sig", Options: []string{"sig", "enc"}},
			},
		},
		{
			ID:       "ecdh-generated",
			HelpText: strptr("Generates ECDH keys"),
			Properties: []ProviderProperty{
				{Name: "priority", Label: "Priority", HelpText: "Priority for the provider", Type: "String", DefaultValue: "0"},
				{Name: "enabled", Label: "Enabled", HelpText: "Set if the keys are enabled", Type: "boolean", DefaultValue: "true"},
				{Name: "active", Label: "Active", HelpText: "Set if the keys can be used for signing", Type: "boolean", DefaultValue: "true"},
				{Name: "ecGenerateCertificate", Label: "Generate Certificate", HelpText: "If a certificate should be build on creation. If the certificate is build, it will be available in the realm JWK for the key in the claim x5c and corresponding thumbprints may be available in the claims like x5t or x5t#S256.", Type: "boolean", DefaultValue: false},
				{Name: "ecdhEllipticCurveKey", Label: "Elliptic Curve", HelpText: "Elliptic Curve used in ECDH", Type: "List", DefaultValue: "P-256", Options: []string{"P-256", "P-384", "P-521"}},
				{Name: "ecdhAlgorithm", Label: "Algorithm", HelpText: "Algorithm for processing the Content Encryption Key", Type: "List", DefaultValue: "ECDH-ES", Options: []string{"ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"}},
			},
		},
		{
			ID:       "rsa-enc-generated",
			HelpText: strptr("Generates RSA keys for key encryption and creates a self-signed certificate"),
			Properties: []ProviderProperty{
				{Name: "priority", Label: "Priority", HelpText: "Priority for the provider", Type: "String", DefaultValue: "0"},
				{Name: "enabled", Label: "Enabled", HelpText: "Set if the keys are enabled", Type: "boolean", DefaultValue: "true"},
				{Name: "active", Label: "Active", HelpText: "Set if the keys can be used for signing", Type: "boolean", DefaultValue: "true"},
				{Name: "keySize", Label: "Key size", HelpText: "Size for the generated keys", Type: "List", DefaultValue: 2048, Options: []string{"1024", "2048", "3072", "4096"}},
				{Name: "algorithm", Label: "Algorithm", HelpText: "Intended algorithm for the key encryption", Type: "List", DefaultValue: "RSA-OAEP", Options: []string{"RSA1_5", "RSA-OAEP", "RSA-OAEP-256"}},
			},
		},
		{
			ID:       "aes-generated",
			HelpText: strptr("Generates AES secret key"),
			Properties: []ProviderProperty{
				{Name: "priority", Label: "Priority", HelpText: "Priority for the provider", Type: "String", DefaultValue: "0"},
				{Name: "enabled", Label: "Enabled", HelpText: "Set if the keys are enabled", Type: "boolean", DefaultValue: "true"},
				{Name: "active", Label: "Active", HelpText: "Set if the keys can be used for signing", Type: "boolean", DefaultValue: "true"},
				{Name: "secretSize", Label: "AES Key size", HelpText: "Size in bytes for the generated AES Key. Size 16 is for AES-128, Size 24 for AES-192 and Size 32 for AES-256.", Type: "List", DefaultValue: "32", Options: []string{"16", "24", "32"}},
			},
		},
		{
			ID:       "ecdsa-generated",
			HelpText: strptr("Generates ECDSA keys"),
			Properties: []ProviderProperty{
				{Name: "priority", Label: "Priority", HelpText: "Priority for the provider", Type: "String", DefaultValue: "0"},
				{Name: "enabled", Label: "Enabled", HelpText: "Set if the keys are enabled", Type: "boolean", DefaultValue: "true"},
				{Name: "active", Label: "Active", HelpText: "Set if the keys can be used for signing", Type: "boolean", DefaultValue: "true"},
				{Name: "ecGenerateCertificate", Label: "Generate Certificate", HelpText: "If a certificate should be build on creation. If the certificate is build, it will be available in the realm JWK for the key in the claim x5c and corresponding thumbprints may be available in the claims like x5t or x5t#S256.", Type: "boolean", DefaultValue: false},
				{Name: "ecdsaEllipticCurveKey", Label: "Elliptic Curve", HelpText: "Elliptic Curve used in ECDSA", Type: "List", DefaultValue: "P-256", Options: []string{"P-256", "P-384", "P-521"}},
			},
		},
		{
			ID:       "rsa-enc",
			HelpText: strptr("RSA for key encryption provider that can optionally generated a self-signed certificate"),
			Properties: []ProviderProperty{
				{Name: "priority", Label: "Priority", HelpText: "Priority for the provider", Type: "String", DefaultValue: "0"},
				{Name: "enabled", Label: "Enabled", HelpText: "Set if the keys are enabled", Type: "boolean", DefaultValue: "true"},
				{Name: "active", Label: "Active", HelpText: "Set if the keys can be used for signing", Type: "boolean", DefaultValue: "true"},
				{Name: "privateKey", Label: "Private RSA Key", HelpText: "Private RSA Key encoded in PEM format", Type: "File", Secret: true},
				{Name: "certificate", Label: "X509 Certificate", HelpText: "X509 Certificate encoded in PEM format", Type: "File"},
				{Name: "algorithm", Label: "Algorithm", HelpText: "Intended algorithm for the key encryption", Type: "List", DefaultValue: "RSA-OAEP", Options: []string{"RSA1_5", "RSA-OAEP", "RSA-OAEP-256"}},
			},
		},
		{
			ID:       "hmac-generated",
			HelpText: strptr("Generates HMAC secret key"),
			Properties: []ProviderProperty{
				{Name: "priority", Label: "Priority", HelpText: "Priority for the provider", Type: "String", DefaultValue: "0"},
				{Name: "enabled", Label: "Enabled", HelpText: "Set if the keys are enabled", Type: "boolean", DefaultValue: "true"},
				{Name: "active", Label: "Active", HelpText: "Set if the keys can be used for signing", Type: "boolean", DefaultValue: "true"},
				{Name: "secretSize", Label: "Secret size", HelpText: "Size in bytes for the generated secret", Type: "List", DefaultValue: "128", Options: []string{"16", "24", "32", "64", "128", "256", "512"}},
				{Name: "algorithm", Label: "Algorithm", HelpText: "Intended algorithm for the key", Type: "List", DefaultValue: "HS512", Options: []string{"HS256", "HS384", "HS512"}},
			},
		},
		{
			ID:       "eddsa-generated",
			HelpText: strptr("Generates EdDSA keys"),
			Properties: []ProviderProperty{
				{Name: "priority", Label: "Priority", HelpText: "Priority for the provider", Type: "String", DefaultValue: "0"},
				{Name: "enabled", Label: "Enabled", HelpText: "Set if the keys are enabled", Type: "boolean", DefaultValue: "true"},
				{Name: "active", Label: "Active", HelpText: "Set if the keys can be used for signing", Type: "boolean", DefaultValue: "true"},
				{Name: "eddsaEllipticCurveKey", Label: "Elliptic Curve", HelpText: "Elliptic Curve used in EdDSA", Type: "List", DefaultValue: "Ed25519", Options: []string{"Ed25519", "Ed448"}},
			},
		},
	},
	"org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy": {
		{
			ID:       "allowed-client-templates",
			HelpText: strptr("When present, it allows to specify whitelist of client scopes, which will be allowed in representation of registered (or updated) client"),
			Properties: []ProviderProperty{
				{Name: "allowed-client-scopes", Label: "allowed-client-scopes.label", HelpText: "allowed-client-scopes.tooltip", Type: "MultivaluedList"},
				{Name: "allow-default-scopes", Label: "allow-default-scopes.label", HelpText: "allow-default-scopes.tooltip", Type: "boolean", DefaultValue: true},
			},
		},
		{
			ID:       "registration-web-origins",
			HelpText: strptr("Allowed web origins for client registration requests"),
			Properties: []ProviderProperty{
				{Name: "web-origins", Label: "registration-web-origins.label", HelpText: "registration-web-origins.tooltip", Type: "MultivaluedString"},
			},
		},
		{
			ID:         "client-disabled",
			HelpText:   strptr("When present, then newly registered client will be disabled and admin needs to manually enable them"),
			Properties: []ProviderProperty{},
		},
		{
			ID:         "scope",
			HelpText:   strptr("When present, then newly registered client won't have full scope allowed"),
			Properties: []ProviderProperty{},
		},
		{
			ID:       "max-clients",
			HelpText: strptr("When present, then it won't be allowed to register new client if count of existing clients in realm is same or bigger than configured limit"),
			Properties: []ProviderProperty{
				{Name: "max-clients", Label: "max-clients.label", HelpText: "max-clients.tooltip", Type: "String", DefaultValue: "200"},
			},
		},
		{
			ID:       "allowed-protocol-mappers",
			HelpText: strptr("When present, it allows to specify whitelist of protocol mapper types, which will be allowed in representation of registered (or updated) client"),
			Properties: []ProviderProperty{
				{Name: "allowed-protocol-mapper-types", Label: "allowed-protocol-mappers.label", HelpText: "allowed-protocol-mappers.tooltip", Type: "MultivaluedList", Options: []string{"oidc-claims-param-token-mapper", "oidc-usermodel-realm-role-mapper", "saml-user-attribute-nameid-mapper", "oidc-claims-param-value-idtoken-mapper", "oidc-usersessionmodel-note-mapper", "saml-authn-context-class-ref-mapper", "oidc-sub-mapper", "oidc-address-mapper", "oidc-organization-group-membership-mapper", "oidc-organization-membership-mapper", "saml-audience-resolve-mapper", "saml-organization-membership-mapper", "saml-user-session-note-mapper", "oidc-role-name-mapper", "oidc-usermodel-client-role-mapper", "oidc-acr-mapper", "oidc-usermodel-property-mapper", "saml-audience-mapper", "saml-group-membership-mapper", "docker-v2-allow-all-mapper", "oidc-hardcoded-role-mapper", "oidc-nonce-backwards-compatible-mapper", "oidc-hardcoded-claim-mapper", "oidc-sha256-pairwise-sub-mapper", "saml-role-name-mapper", "saml-user-property-mapper", "oidc-amr-mapper", "saml-role-list-mapper", "oidc-full-name-mapper", "oidc-allowed-origins-mapper", "oidc-audience-mapper", "oidc-usermodel-attribute-mapper", "oidc-session-state-mapper", "saml-hardcode-attribute-mapper", "oidc-group-membership-mapper", "saml-user-attribute-mapper", "saml-organization-group-membership-mapper", "saml-hardcode-role-mapper", "oidc-audience-resolve-mapper"}},
			},
		},
		{
			ID:       "trusted-hosts",
			HelpText: strptr("Allows to specify from which hosts is user able to register and which redirect URIs can client use in it's configuration"),
			Properties: []ProviderProperty{
				{Name: "trusted-hosts", Label: "trusted-hosts.label", HelpText: "trusted-hosts.tooltip", Type: "MultivaluedString"},
				{Name: "host-sending-registration-request-must-match", Label: "host-sending-registration-request-must-match.label", HelpText: "host-sending-registration-request-must-match.tooltip", Type: "boolean", DefaultValue: "true"},
				{Name: "client-uris-must-match", Label: "client-uris-must-match.label", HelpText: "client-uris-must-match.tooltip", Type: "boolean", DefaultValue: "true"},
			},
		},
		{
			ID:         "consent-required",
			HelpText:   strptr("When present, then newly registered client will always have 'consentRequired' switch enabled"),
			Properties: []ProviderProperty{},
		},
	},
	"org.keycloak.storage.UserStorageProvider": {
		{
			ID:       "ldap",
			HelpText: strptr(""),
			Properties: []ProviderProperty{
				{Name: "editMode", Type: "String"},
				{Name: "importEnabled", Type: "boolean", DefaultValue: "true"},
				{Name: "syncRegistrations", Type: "boolean", DefaultValue: "false"},
				{Name: "vendor", Type: "String"},
				{Name: "usePasswordModifyExtendedOp", Type: "boolean"},
				{Name: "usernameLDAPAttribute", Type: "String"},
				{Name: "rdnLDAPAttribute", Type: "String"},
				{Name: "uuidLDAPAttribute", Type: "String"},
				{Name: "userObjectClasses", Type: "String"},
				{Name: "connectionUrl", Type: "String"},
				{Name: "usersDn", Type: "String"},
				{Name: "relativeCreateDn", Type: "String"},
				{Name: "authType", Type: "String", DefaultValue: "simple"},
				{Name: "startTls", Type: "boolean"},
				{Name: "bindDn", Type: "String"},
				{Name: "bindCredential", Type: "Password", Secret: true},
				{Name: "customUserSearchFilter", Type: "String"},
				{Name: "searchScope", Type: "String", DefaultValue: "1"},
				{Name: "validatePasswordPolicy", Type: "boolean", DefaultValue: "false"},
				{Name: "trustEmail", Type: "boolean", DefaultValue: "false"},
				{Name: "useTruststoreSpi", Type: "String", DefaultValue: "always"},
				{Name: "connectionPooling", Type: "boolean", DefaultValue: "true"},
				{Name: "connectionTimeout", Type: "String"},
				{Name: "readTimeout", Type: "String"},
				{Name: "pagination", Type: "boolean", DefaultValue: "true"},
				{Name: "referral", Type: "String"},
				{Name: "allowKerberosAuthentication", Type: "boolean", DefaultValue: "false"},
				{Name: "serverPrincipal", Type: "String"},
				{Name: "keyTab", Type: "String"},
				{Name: "kerberosRealm", Type: "String"},
				{Name: "krbPrincipalAttribute", Type: "String"},
				{Name: "debug", Type: "boolean", DefaultValue: "false"},
				{Name: "useKerberosForPasswordAuthentication", Type: "boolean", DefaultValue: "false"},
				{Name: "connectionTrace", Type: "boolean", DefaultValue: "false"},
				{Name: "enableLdapPasswordPolicy", Type: "boolean", DefaultValue: "false"},
			},
			Metadata: []ComponentTypeMetadata{
				{Name: "synchronizable", Value: true},
			},
		},
		{
			ID:       "kerberos",
			HelpText: strptr(""),
			Properties: []ProviderProperty{
				{Name: "kerberosRealm", Label: "kerberos-realm", HelpText: "kerberos-realm.tooltip", Type: "String"},
				{Name: "serverPrincipal", Label: "server-principal", HelpText: "server-principal.tooltip", Type: "String"},
				{Name: "keyTab", Label: "keytab", HelpText: "keytab.tooltip", Type: "String"},
				{Name: "debug", Label: "debug", HelpText: "debug.tooltip", Type: "boolean", DefaultValue: "false"},
				{Name: "allowPasswordAuthentication", Label: "allow-password-authentication", HelpText: "allow-password-authentication.tooltip", Type: "boolean", DefaultValue: "false"},
				{Name: "editMode", Label: "edit-mode", HelpText: "edit-mode.tooltip", Type: "List", Options: []string{"READ_ONLY", "UNSYNCED"}},
				{Name: "updateProfileFirstLogin", Label: "update-profile-first-login", HelpText: "update-profile-first-login.tooltip", Type: "boolean", DefaultValue: "false"},
			},
		},
	},
	"org.keycloak.storage.ldap.mappers.LDAPStorageMapper": {
		{
			ID:         "kerberos-principal-attribute-mapper",
			HelpText:   strptr("This mapper will update Kerberos principal attribute in the DB when the attribute changes in LDAP."),
			Properties: []ProviderProperty{},
			Metadata: []ComponentTypeMetadata{
				{Name: "fedToKeycloakSyncSupported", Value: false},
				{Name: "keycloakToFedSyncSupported", Value: false},
			},
		},
		{
			ID:       "msad-user-account-control-mapper",
			HelpText: strptr("Mapper specific to MSAD. It's able to integrate the MSAD user account state into Keycloak account state (account enabled, password is expired etc). It's using userAccountControl and pwdLastSet MSAD attributes for that. For example if pwdLastSet is 0, the Keycloak user is required to update password, if userAccountControl is 514 (disabled account) the Keycloak user is disabled as well etc. Mapper is also able to handle exception code from LDAP user authentication."),
			Properties: []ProviderProperty{
				{Name: "ldap.password.policy.hints.enabled", Label: "Password Policy Hints Enabled", HelpText: "Applicable just for writable MSAD. If on, then updating password of MSAD user will use LDAP_SERVER_POLICY_HINTS_OID extension, which means that advanced MSAD password policies like 'password history' or 'minimal password age' will be applied. This extension works just for MSAD 2008 R2 or newer.", Type: "boolean", DefaultValue: "false"},
				{Name: "always.read.enabled.value.from.ldap", Label: "Always Read Enabled Value From LDAP", HelpText: "If on, the user enabled/disabled state will always be read from MSAD by checking the proper userAccountControl", Type: "boolean", DefaultValue: "false"},
			},
			Metadata: []ComponentTypeMetadata{
				{Name: "fedToKeycloakSyncSupported", Value: false},
				{Name: "keycloakToFedSyncSupported", Value: false},
			},
		},
		{
			ID:       "msad-lds-user-account-control-mapper",
			HelpText: strptr("Mapper specific to MSAD LDS. It's able to integrate the MSAD LDS user account state into Keycloak account state (account enabled, password is expired etc). It's using msDS-UserAccountDisabled and pwdLastSet MSAD attributes for that. For example if pwdLastSet is 0, the Keycloak user is required to update password, if msDS-UserAccountDisabled is 'TRUE' the Keycloak user is disabled as well etc. Mapper is also able to handle exception code from LDAP user authentication."),
			Properties: []ProviderProperty{
				{Name: "always.read.enabled.value.from.ldap", Label: "Always Read Enabled Value From LDAP", HelpText: "If on, the user enabled/disabled state will always be read from MSAD LDS by checking the msDS-UserAccountDisabled attribute", Type: "boolean", DefaultValue: "false"},
			},
			Metadata: []ComponentTypeMetadata{
				{Name: "fedToKeycloakSyncSupported", Value: false},
				{Name: "keycloakToFedSyncSupported", Value: false},
			},
		},
		{
			ID:       "group-ldap-mapper",
			HelpText: strptr("Used to map group mappings of groups from some LDAP DN to Keycloak group mappings"),
			Properties: []ProviderProperty{
				{Name: "groups.dn", Label: "LDAP Groups DN", HelpText: "LDAP DN where groups of this tree are saved. For example 'ou=groups,dc=example,dc=org' ", Type: "String", Required: true},
				{Name: "groups.relative.create.dn", Label: "Relative creation DN", HelpText: "LDAP DN where groups of this tree will be created relative to the 'LDAP Groups DN' ", Type: "String"},
				{Name: "group.name.ldap.attribute", Label: "Group Name LDAP Attribute", HelpText: "Name of LDAP attribute, which is used in group objects for name and RDN of group. Usually it will be 'cn' . In this case typical group/role object may have DN like 'cn=Group1,ou=groups,dc=example,dc=org' ", Type: "String", DefaultValue: "cn"},
				{Name: "group.object.classes", Label: "Group Object Classes", HelpText: "Object class (or classes) of the group object. It's divided by comma if more classes needed. In typical LDAP deployment it could be 'groupOfNames' . In Active Directory it's usually 'group' ", Type: "String", DefaultValue: "groupOfNames"},
				{Name: "preserve.group.inheritance", Label: "Preserve Group Inheritance", HelpText: "Flag whether group inheritance from LDAP should be propagated to Keycloak. If false, then all LDAP groups will be mapped as flat top-level groups in Keycloak. Otherwise group inheritance is preserved into Keycloak, but the group sync might fail if LDAP structure contains recursions or multiple parent groups per child groups", Type: "boolean", DefaultValue: "true"},
				{Name: "ignore.missing.groups", Label: "Ignore Missing Groups", HelpText: "Ignore missing groups in the group hierarchy", Type: "boolean", DefaultValue: "false"},
				{Name: "membership.ldap.attribute", Label: "Membership LDAP Attribute", HelpText: "Name of LDAP attribute on group, which is used for membership mappings. Usually it will be 'member' .However when 'Membership Attribute Type' is 'UID' then 'Membership LDAP Attribute' could be typically 'memberUid' .", Type: "String", DefaultValue: "member"},
				{Name: "membership.attribute.type", Label: "Membership Attribute Type", HelpText: "DN means that LDAP group has it's members declared in form of their full DN. For example 'member: uid=john,ou=users,dc=example,dc=com' . UID means that LDAP group has it's members declared in form of pure user uids. For example 'memberUid: john' .", Type: "List", DefaultValue: "DN", Options: []string{"DN", "UID"}},
				{Name: "membership.user.ldap.attribute", Label: "Membership User LDAP Attribute", HelpText: "Used just if Membership Attribute Type is UID. It is name of LDAP attribute on user, which is used for membership mappings. Usually it will be 'uid' . For example if value of 'Membership User LDAP Attribute' is 'uid' and  LDAP group has  'memberUid: john', then it is expected that particular LDAP user will have attribute 'uid: john' .", Type: "String", DefaultValue: "uid"},
				{Name: "groups.ldap.filter", Label: "LDAP Filter", HelpText: "LDAP Filter adds additional custom filter to the whole query for retrieve LDAP groups. Leave this empty if no additional filtering is needed and you want to retrieve all groups from LDAP. Otherwise make sure that filter starts with '(' and ends with ')'", Type: "String"},
				{Name: "mode", Label: "Mode", HelpText: "LDAP_ONLY means that all group mappings of users are retrieved from LDAP and saved into LDAP. READ_ONLY is Read-only LDAP mode where group mappings are retrieved from both LDAP and DB and merged together. New group joins are not saved to LDAP but to DB. IMPORT is Read-only LDAP mode where group mappings are retrieved from LDAP just at the time when user is imported from LDAP and then they are saved to local keycloak DB.", Type: "List", DefaultValue: "READ_ONLY", Options: []string{"LDAP_ONLY", "IMPORT", "READ_ONLY"}},
				{Name: "user.roles.retrieve.strategy", Label: "User Groups Retrieve Strategy", HelpText: "Specify how to retrieve groups of user. LOAD_GROUPS_BY_MEMBER_ATTRIBUTE means that roles of user will be retrieved by sending LDAP query to retrieve all groups where 'member' is our user. GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE means that groups of user will be retrieved from 'memberOf' attribute of our user. Or from the other attribute specified by 'Member-Of LDAP Attribute' . ", Type: "List", DefaultValue: "LOAD_GROUPS_BY_MEMBER_ATTRIBUTE", Options: []string{"LOAD_GROUPS_BY_MEMBER_ATTRIBUTE", "GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE"}},
				{Name: "memberof.ldap.attribute", Label: "Member-Of LDAP Attribute", HelpText: "Used just when 'User Roles Retrieve Strategy' is GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE . It specifies the name of the LDAP attribute on the LDAP user, which contains the groups, which the user is member of. Usually it will be 'memberOf' and that's also the default value.", Type: "String", DefaultValue: "memberOf"},
				{Name: "mapped.group.attributes", Label: "Mapped Group Attributes", HelpText: "List of names of attributes divided by comma. This points to the list of attributes on LDAP group, which will be mapped as attributes of Group in Keycloak. Leave this empty if no additional group attributes are required to be mapped in Keycloak. ", Type: "String"},
				{Name: "decode.group.uuid.attribute", Label: "Decode UUID Attribute to UUID Format", HelpText: "If on, the UUID LDAP attribute (e.g. objectGUID in Active Directory) listed in 'Mapped Group Attributes' is decoded to UUID string format. If off, the attribute is kept as a base64-encoded string.", Type: "boolean", DefaultValue: "true"},
				{Name: "drop.non.existing.groups.during.sync", Label: "Drop non-existing groups during sync", HelpText: "If this flag is true, then during sync of groups from LDAP to Keycloak, we will keep just those Keycloak groups, which still exists in LDAP. Rest will be deleted", Type: "boolean", DefaultValue: "false"},
				{Name: "groups.path", Label: "Groups Path", HelpText: "Keycloak group path the LDAP groups are added to. For example if value '/Applications/App1' is used, then LDAP groups will be available in Keycloak under group 'App1', which is child of top level group 'Applications'. The default value is '/' so LDAP groups will be mapped to the Keycloak groups at the top level. The configured group path must already exists in the Keycloak when creating this mapper.", Type: "String", DefaultValue: "/"},
			},
			Metadata: []ComponentTypeMetadata{
				{Name: "fedToKeycloakSyncSupported", Value: true},
				{Name: "keycloakToFedSyncSupported", Value: true},
				{Name: "fedToKeycloakSyncMessage", Value: "sync-ldap-groups-to-keycloak"},
				{Name: "keycloakToFedSyncMessage", Value: "sync-keycloak-groups-to-ldap"},
			},
		},
		{
			ID:       "user-attribute-ldap-mapper",
			HelpText: strptr("Used to map single attribute from LDAP user to attribute of UserModel in Keycloak DB"),
			Properties: []ProviderProperty{
				{Name: "user.model.attribute", Label: "User Model Attribute", HelpText: "Name of the UserModel property or attribute you want to map the LDAP attribute into. For example 'firstName', 'lastName, 'email', 'street' etc.", Type: "UserProfileAttributeList", Required: true},
				{Name: "ldap.attribute", Label: "LDAP Attribute", HelpText: "Name of mapped attribute on LDAP object. For example 'cn', 'sn, 'mail', 'street' etc.", Type: "String", Required: true},
				{Name: "read.only", Label: "Read Only", HelpText: "Read-only attribute is imported from LDAP to UserModel, but it's not saved back to LDAP when user is updated in Keycloak.", Type: "boolean", DefaultValue: "true"},
				{Name: "always.read.value.from.ldap", Label: "Always Read Value From LDAP", HelpText: "If on, then during reading of the LDAP attribute value will always used instead of the value from Keycloak DB", Type: "boolean", DefaultValue: "false"},
				{Name: "is.binary.attribute", Label: "Is Binary Attribute", HelpText: "Should be true for binary LDAP attributes", Type: "boolean", DefaultValue: "false"},
				{Name: "binary.attribute.decoder", Label: "Decode Binary Attribute As", HelpText: "Controls how binary attribute values are decoded. 'auto' decodes as UUID when the LDAP attribute matches the UUID LDAP attribute (e.g. objectGUID), base64 otherwise. 'base64' always returns a base64-encoded string. 'uuid' always decodes the value as a UUID/GUID. If 'uuid' or 'auto' is selected but the binary value is not 16 bytes (the size of a UUID), it falls back to base64 encoding.", Type: "List", Options: []string{"auto", "base64", "uuid"}},
				{Name: "is.mandatory.in.ldap", Label: "Is Mandatory In LDAP", HelpText: "If true, attribute is mandatory in LDAP. When an attribute is mandatory the options attribute default value and force a default value apply to this mapper.", Type: "boolean", DefaultValue: "false"},
				{Name: "attribute.default.value", Label: "Attribute default value", HelpText: "If there is no value in Keycloak DB and attribute is mandatory in LDAP, this value will be propagated to LDAP", Type: "String", DefaultValue: ""},
				{Name: "attribute.force.default", Label: "Force a Default Value", HelpText: "If true a empty default value is forced for mandatory attributes even when a default value is not specified. If false the mandatory attribute needs to be manually set during the transaction when the default value option is not configured.", Type: "boolean", DefaultValue: "true"},
			},
			Metadata: []ComponentTypeMetadata{
				{Name: "fedToKeycloakSyncSupported", Value: false},
				{Name: "keycloakToFedSyncSupported", Value: false},
			},
		},
		{
			ID:       "role-ldap-mapper",
			HelpText: strptr("Used to map role mappings of roles from some LDAP DN to Keycloak role mappings of either realm roles or client roles of particular client"),
			Properties: []ProviderProperty{
				{Name: "roles.dn", Label: "LDAP Roles DN", HelpText: "LDAP DN where are roles of this tree saved. For example 'ou=finance,dc=example,dc=org' ", Type: "String", Required: true},
				{Name: "roles.relative.create.dn", Label: "Relative creation DN", HelpText: "LDAP DN where are roles of this tree will be created relative to the 'LDAP Roles DN' ", Type: "String"},
				{Name: "role.name.ldap.attribute", Label: "Role Name LDAP Attribute", HelpText: "Name of LDAP attribute, which is used in role objects for name and RDN of role. Usually it will be 'cn' . In this case typical group/role object may have DN like 'cn=role1,ou=finance,dc=example,dc=org' ", Type: "String", DefaultValue: "cn"},
				{Name: "role.object.classes", Label: "Role Object Classes", HelpText: "Object class (or classes) of the role object. It's divided by comma if more classes needed. In typical LDAP deployment it could be 'groupOfNames' . In Active Directory it's usually 'group' ", Type: "String", DefaultValue: "groupOfNames"},
				{Name: "membership.ldap.attribute", Label: "Membership LDAP Attribute", HelpText: "Name of LDAP attribute on role, which is used for membership mappings. Usually it will be 'member' .However when 'Membership Attribute Type' is 'UID' then 'Membership LDAP Attribute' could be typically 'memberUid' .", Type: "String", DefaultValue: "member"},
				{Name: "membership.attribute.type", Label: "Membership Attribute Type", HelpText: "DN means that LDAP role has it's members declared in form of their full DN. For example 'member: uid=john,ou=users,dc=example,dc=com' . UID means that LDAP role has it's members declared in form of pure user uids. For example 'memberUid: john' .", Type: "List", DefaultValue: "DN", Options: []string{"DN", "UID"}},
				{Name: "membership.user.ldap.attribute", Label: "Membership User LDAP Attribute", HelpText: "Used just if Membership Attribute Type is UID. It is name of LDAP attribute on user, which is used for membership mappings. Usually it will be 'uid' . For example if value of 'Membership User LDAP Attribute' is 'uid' and  LDAP group has  'memberUid: john', then it is expected that particular LDAP user will have attribute 'uid: john' .", Type: "String", DefaultValue: "uid"},
				{Name: "roles.ldap.filter", Label: "LDAP Filter", HelpText: "LDAP Filter adds additional custom filter to the whole query for retrieve LDAP roles. Leave this empty if no additional filtering is needed and you want to retrieve all roles from LDAP. Otherwise make sure that filter starts with '(' and ends with ')'", Type: "String"},
				{Name: "mode", Label: "Mode", HelpText: "LDAP_ONLY means that all role mappings are retrieved from LDAP and saved into LDAP. READ_ONLY is Read-only LDAP mode where role mappings are retrieved from both LDAP and DB and merged together. New role grants are not saved to LDAP but to DB. IMPORT is Read-only LDAP mode where role mappings are retrieved from LDAP just at the time when user is imported from LDAP and then they are saved to local keycloak DB.", Type: "List", DefaultValue: "READ_ONLY", Options: []string{"LDAP_ONLY", "IMPORT", "READ_ONLY"}},
				{Name: "user.roles.retrieve.strategy", Label: "User Roles Retrieve Strategy", HelpText: "Specify how to retrieve roles of user. LOAD_ROLES_BY_MEMBER_ATTRIBUTE means that roles of user will be retrieved by sending LDAP query to retrieve all roles where 'member' is our user. GET_ROLES_FROM_USER_MEMBEROF_ATTRIBUTE means that roles of user will be retrieved from 'memberOf' attribute of our user. Or from the other attribute specified by 'Member-Of LDAP Attribute' . ", Type: "List", DefaultValue: "LOAD_ROLES_BY_MEMBER_ATTRIBUTE", Options: []string{"LOAD_ROLES_BY_MEMBER_ATTRIBUTE", "GET_ROLES_FROM_USER_MEMBEROF_ATTRIBUTE"}},
				{Name: "memberof.ldap.attribute", Label: "Member-Of LDAP Attribute", HelpText: "Used just when 'User Roles Retrieve Strategy' is GET_ROLES_FROM_USER_MEMBEROF_ATTRIBUTE . It specifies the name of the LDAP attribute on the LDAP user, which contains the roles (LDAP Groups), which the user is member of. Usually it will be 'memberOf' and that's also the default value.", Type: "String", DefaultValue: "memberOf"},
				{Name: "use.realm.roles.mapping", Label: "Use Realm Roles Mapping", HelpText: "If true, then LDAP role mappings will be mapped to realm role mappings in Keycloak. Otherwise it will be mapped to client role mappings", Type: "boolean", DefaultValue: "true"},
				{Name: "client.id", Label: "Client ID", HelpText: "Client ID of client to which LDAP role mappings will be mapped. Applicable just if 'Use Realm Roles Mapping' is false", Type: "ClientList"},
			},
			Metadata: []ComponentTypeMetadata{
				{Name: "fedToKeycloakSyncSupported", Value: true},
				{Name: "keycloakToFedSyncSupported", Value: true},
				{Name: "fedToKeycloakSyncMessage", Value: "sync-ldap-roles-to-keycloak"},
				{Name: "keycloakToFedSyncMessage", Value: "sync-keycloak-roles-to-ldap"},
			},
		},
		{
			ID:       "hardcoded-attribute-mapper",
			HelpText: strptr("This mapper will hardcode any model user attribute and some property (like emailVerified or enabled) when importing user from ldap."),
			Properties: []ProviderProperty{
				{Name: "user.model.attribute", Label: "User Model Attribute Name", HelpText: "Name of the model attribute, which will be added when importing user from ldap", Type: "UserProfileAttributeList", Required: true},
				{Name: "attribute.value", Label: "Attribute Value", HelpText: "Value of the model attribute, which will be added when importing user from ldap.", Type: "String", Required: true},
			},
			Metadata: []ComponentTypeMetadata{
				{Name: "fedToKeycloakSyncSupported", Value: false},
				{Name: "keycloakToFedSyncSupported", Value: false},
			},
		},
		{
			ID:       "hardcoded-ldap-role-mapper",
			HelpText: strptr("When user is imported from LDAP, he will be automatically added into this configured role."),
			Properties: []ProviderProperty{
				{Name: "role", Label: "Role", HelpText: "Role to grant to user.  Click 'Select Role' button to browse roles, or just type it in the textbox.  To reference a client role the syntax is clientname.clientrole, i.e. myclient.myrole", Type: "Role", Required: true},
			},
			Metadata: []ComponentTypeMetadata{
				{Name: "fedToKeycloakSyncSupported", Value: false},
				{Name: "keycloakToFedSyncSupported", Value: false},
			},
		},
		{
			ID:       "certificate-ldap-mapper",
			HelpText: strptr("Used to map single attribute which contains a certificate from LDAP user to attribute of UserModel in Keycloak DB"),
			Properties: []ProviderProperty{
				{Name: "user.model.attribute", Label: "User Model Attribute", HelpText: "Name of the UserModel property or attribute you want to map the LDAP attribute into. For example 'firstName', 'lastName, 'email', 'street' etc.", Type: "UserProfileAttributeList", Required: true},
				{Name: "ldap.attribute", Label: "LDAP Attribute", HelpText: "Name of mapped attribute on LDAP object. For example 'cn', 'sn, 'mail', 'street' etc.", Type: "String", Required: true},
				{Name: "read.only", Label: "Read Only", HelpText: "Read-only attribute is imported from LDAP to UserModel, but it's not saved back to LDAP when user is updated in Keycloak.", Type: "boolean", DefaultValue: "false"},
				{Name: "always.read.value.from.ldap", Label: "Always Read Value From LDAP", HelpText: "If on, then during reading of the LDAP attribute value will always used instead of the value from Keycloak DB", Type: "boolean", DefaultValue: "false"},
				{Name: "is.binary.attribute", Label: "Is Binary Attribute", HelpText: "Should be true for binary LDAP attributes", Type: "boolean", DefaultValue: "false"},
				{Name: "binary.attribute.decoder", Label: "Decode Binary Attribute As", HelpText: "Controls how binary attribute values are decoded. 'auto' decodes as UUID when the LDAP attribute matches the UUID LDAP attribute (e.g. objectGUID), base64 otherwise. 'base64' always returns a base64-encoded string. 'uuid' always decodes the value as a UUID/GUID. If 'uuid' or 'auto' is selected but the binary value is not 16 bytes (the size of a UUID), it falls back to base64 encoding.", Type: "List", Options: []string{"auto", "base64", "uuid"}},
				{Name: "is.mandatory.in.ldap", Label: "Is Mandatory In LDAP", HelpText: "If true, attribute is mandatory in LDAP. When an attribute is mandatory the options attribute default value and force a default value apply to this mapper.", Type: "boolean", DefaultValue: "false"},
				{Name: "attribute.default.value", Label: "Attribute default value", HelpText: "If there is no value in Keycloak DB and attribute is mandatory in LDAP, this value will be propagated to LDAP", Type: "String", DefaultValue: ""},
				{Name: "attribute.force.default", Label: "Force a Default Value", HelpText: "If true a empty default value is forced for mandatory attributes even when a default value is not specified. If false the mandatory attribute needs to be manually set during the transaction when the default value option is not configured.", Type: "boolean", DefaultValue: "true"},
				{Name: "is.der.formatted", Label: "DER Formatted", HelpText: "Activate this if the certificate is DER formatted in LDAP and not PEM formatted.", Type: "boolean"},
			},
			Metadata: []ComponentTypeMetadata{
				{Name: "fedToKeycloakSyncSupported", Value: false},
				{Name: "keycloakToFedSyncSupported", Value: false},
			},
		},
		{
			ID:       "full-name-ldap-mapper",
			HelpText: strptr("Used to map full-name of user from single attribute in LDAP (usually 'cn' attribute) to firstName and lastName attributes of UserModel in Keycloak DB"),
			Properties: []ProviderProperty{
				{Name: "ldap.full.name.attribute", Label: "LDAP Full Name Attribute", HelpText: "Name of LDAP attribute, which contains fullName of user. Usually it will be 'cn' ", Type: "String", DefaultValue: "cn"},
				{Name: "read.only", Label: "Read Only", HelpText: "For Read-only is data imported from LDAP to Keycloak DB, but it's not saved back to LDAP when user is updated in Keycloak.", Type: "boolean", DefaultValue: "true"},
				{Name: "write.only", Label: "Write Only", HelpText: "For Write-only is data propagated to LDAP when user is created or updated in Keycloak. But this mapper is not used to propagate data from LDAP back into Keycloak. This setting is useful if you configured separate firstName and lastName attribute mappers and you want to use those to read attribute from LDAP into Keycloak", Type: "boolean", DefaultValue: "false"},
			},
			Metadata: []ComponentTypeMetadata{
				{Name: "fedToKeycloakSyncSupported", Value: false},
				{Name: "keycloakToFedSyncSupported", Value: false},
			},
		},
		{
			ID:       "hardcoded-ldap-group-mapper",
			HelpText: strptr("When user is imported from LDAP, he will be automatically added into this configured group."),
			Properties: []ProviderProperty{
				{Name: "group", Label: "Group", HelpText: "Group to add the user in. Fill the full path of the group including path. For example '/root-group/child-group'", Type: "String", Required: true},
			},
			Metadata: []ComponentTypeMetadata{
				{Name: "fedToKeycloakSyncSupported", Value: false},
				{Name: "keycloakToFedSyncSupported", Value: false},
			},
		},
		{
			ID:       "hardcoded-ldap-attribute-mapper",
			HelpText: strptr("This mapper is supported just if syncRegistrations is enabled. When new user is registered in Keycloak, he will be written to the LDAP with the hardcoded value of some specified attribute."),
			Properties: []ProviderProperty{
				{Name: "ldap.attribute.name", Label: "LDAP Attribute Name", HelpText: "Name of the LDAP attribute, which will be added to the new user during registration", Type: "String", Required: true},
				{Name: "ldap.attribute.value", Label: "LDAP Attribute Value", HelpText: "Value of the LDAP attribute, which will be added to the new user during registration. You can either hardcode any value like 'foo' but you can also use some special tokens. Only supported token right now is '${RANDOM}' , which will be replaced with some randomly generated String.", Type: "String", Required: true},
			},
			Metadata: []ComponentTypeMetadata{
				{Name: "fedToKeycloakSyncSupported", Value: false},
				{Name: "keycloakToFedSyncSupported", Value: false},
			},
		},
	},
	"org.keycloak.userprofile.UserProfileProvider": {
		{
			ID: "declarative-user-profile",
			Properties: []ProviderProperty{
				{Name: "kc.user.profile.config", Type: "String"},
			},
		},
	},
}

// componentProviderRegistry is every (providerType, providerId) pair
// `GET /admin/serverinfo` registers - 245 of them over 18 types, in the
// server's own order.
//
// It is here because `POST /components` answers **three** different things
// for a provider it will not create, and only a registry tells them apart:
// a pair that does not resolve at all is a 400, a Workflow pair is a 403 and
// any other registered pair is a 500. Measured over all eighteen types.
var componentProviderRegistry = map[string][]string{
	"org.keycloak.authentication.FormAction": {
		"registration-password-action", "registration-recaptcha-action",
		"registration-recaptcha-enterprise", "registration-terms-and-conditions",
		"registration-user-creation",
	},
	"org.keycloak.authentication.Authenticator": {
		"allow-access-authenticator", "auth-conditional-otp-form", "auth-cookie", "auth-otp-form",
		"auth-password-form", "auth-recovery-authn-code-form", "auth-spnego", "auth-username-form",
		"auth-username-password-form", "auth-x509-client-username-form", "conditional-client-scope",
		"conditional-credential", "conditional-level-of-authentication",
		"conditional-sub-flow-executed", "conditional-user-attribute", "conditional-user-configured",
		"conditional-user-role", "deny-access-authenticator", "direct-grant-auth-x509-username",
		"direct-grant-validate-otp", "direct-grant-validate-password",
		"direct-grant-validate-username", "docker-http-basic-authenticator",
		"http-basic-authenticator", "identity-provider-redirector", "idp-add-organization-member",
		"idp-auto-link", "idp-confirm-link", "idp-confirm-override-link",
		"idp-create-user-if-unique", "idp-detect-existing-broker-user", "idp-email-verification",
		"idp-review-profile", "idp-username-password-form", "organization", "reset-credential-email",
		"reset-credentials-choose-user", "reset-otp", "reset-password", "user-session-limits",
		"webauthn-authenticator", "webauthn-authenticator-passwordless",
	},
	"org.keycloak.storage.UserStorageProvider": {
		"kerberos", "ldap",
	},
	"org.keycloak.storage.ldap.mappers.LDAPStorageMapper": {
		"certificate-ldap-mapper", "full-name-ldap-mapper", "group-ldap-mapper",
		"hardcoded-attribute-mapper", "hardcoded-ldap-attribute-mapper",
		"hardcoded-ldap-group-mapper", "hardcoded-ldap-role-mapper",
		"kerberos-principal-attribute-mapper", "msad-lds-user-account-control-mapper",
		"msad-user-account-control-mapper", "role-ldap-mapper", "user-attribute-ldap-mapper",
	},
	"org.keycloak.broker.social.SocialIdentityProvider": {
		"bitbucket", "facebook", "github", "gitlab", "google", "linkedin-openid-connect",
		"microsoft", "openshift-v4", "paypal", "stackoverflow", "twitter",
	},
	"org.keycloak.authentication.ClientAuthenticator": {
		"client-jwt", "client-secret", "client-secret-jwt", "client-x509", "federated-jwt",
	},
	"org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy": {
		"allowed-client-templates", "allowed-protocol-mappers", "client-disabled",
		"consent-required", "max-clients", "registration-web-origins", "scope", "trusted-hosts",
	},
	"org.keycloak.validate.Validator": {
		"double", "email", "integer", "iso-date", "length", "local-date", "multivalued", "options",
		"pattern", "person-name-prohibited-characters", "up-username-not-idn-homograph", "uri",
		"username-prohibited-characters",
	},
	"org.keycloak.userprofile.UserProfileProvider": {
		"declarative-user-profile",
	},
	"org.keycloak.keys.KeyProvider": {
		"aes-generated", "ecdh-generated", "ecdsa-generated", "eddsa-generated", "hmac-generated",
		"java-keystore", "rsa", "rsa-enc", "rsa-enc-generated", "rsa-generated",
	},
	"org.keycloak.authentication.FormAuthenticator": {
		"registration-page-form",
	},
	"org.keycloak.protocol.ProtocolMapper": {
		"docker-v2-allow-all-mapper", "oidc-acr-mapper", "oidc-address-mapper",
		"oidc-allowed-origins-mapper", "oidc-amr-mapper", "oidc-audience-mapper",
		"oidc-audience-resolve-mapper", "oidc-claims-param-token-mapper",
		"oidc-claims-param-value-idtoken-mapper", "oidc-full-name-mapper",
		"oidc-group-membership-mapper", "oidc-hardcoded-claim-mapper", "oidc-hardcoded-role-mapper",
		"oidc-nonce-backwards-compatible-mapper", "oidc-organization-group-membership-mapper",
		"oidc-organization-membership-mapper", "oidc-role-name-mapper", "oidc-session-state-mapper",
		"oidc-sha256-pairwise-sub-mapper", "oidc-sub-mapper", "oidc-usermodel-attribute-mapper",
		"oidc-usermodel-client-role-mapper", "oidc-usermodel-property-mapper",
		"oidc-usermodel-realm-role-mapper", "oidc-usersessionmodel-note-mapper",
		"saml-audience-mapper", "saml-audience-resolve-mapper",
		"saml-authn-context-class-ref-mapper", "saml-group-membership-mapper",
		"saml-hardcode-attribute-mapper", "saml-hardcode-role-mapper",
		"saml-organization-group-membership-mapper", "saml-organization-membership-mapper",
		"saml-role-list-mapper", "saml-role-name-mapper", "saml-user-attribute-mapper",
		"saml-user-attribute-nameid-mapper", "saml-user-property-mapper",
		"saml-user-session-note-mapper",
	},
	"org.keycloak.services.clientpolicy.condition.ClientPolicyConditionProvider": {
		"acr-condition", "any-client", "client-access-type", "client-attributes", "client-roles",
		"client-scopes", "client-type", "client-updater-context", "client-updater-source-groups",
		"client-updater-source-host", "client-updater-source-roles", "grant-type",
		"identity-provider-alias",
	},
	"org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProvider": {
		"auth-flow-enforcer", "confidential-client", "consent-required",
		"downscope-assertion-grant-enforcer", "dpop-bind-enforcer", "full-scope-disabled",
		"holder-of-key-enforcer", "intent-client-bind-checker", "jwt-claim-enforcer",
		"pkce-enforcer", "registration-access-token-rotation-disabled", "reject-implicit-grant",
		"reject-request", "reject-ropc-grant", "saml-avoid-redirect", "saml-secure-client-uris",
		"saml-signature-enforcer", "secure-ciba-req-sig-algorithm", "secure-ciba-session",
		"secure-ciba-signed-authn-req", "secure-client-authentication-assertion",
		"secure-client-authenticator", "secure-client-uris", "secure-client-uris-pattern",
		"secure-logout", "secure-par-content", "secure-redirect-uris-enforcer",
		"secure-request-object", "secure-response-type", "secure-session",
		"secure-signature-algorithm", "secure-signature-algorithm-signed-jwt",
		"suppress-refresh-token-rotation", "tls-client-auth-ca-subject-dn",
		"use-lightweight-access-token",
	},
	"org.keycloak.models.workflow.WorkflowStepProvider": {
		"add-required-action", "delete-client", "delete-user", "disable-client", "disable-user",
		"grant-role", "join-group", "leave-group", "notify-user", "remove-required-action",
		"remove-user-attribute", "restart", "revoke-role", "set-user-attribute", "unlink-user",
	},
	"org.keycloak.models.workflow.WorkflowProvider": {
		"default",
	},
	"org.keycloak.broker.provider.IdentityProvider": {
		"jwt-authorization-grant", "keycloak-oidc", "kubernetes", "oauth2", "oidc", "saml",
	},
	"org.keycloak.broker.provider.IdentityProviderMapper": {
		"facebook-user-attribute-mapper", "github-user-attribute-mapper",
		"google-user-attribute-mapper", "hardcoded-attribute-idp-mapper",
		"hardcoded-user-session-attribute-idp-mapper", "instagram-user-attribute-mapper",
		"keycloak-oidc-role-to-role-idp-mapper", "linkedin-user-attribute-mapper",
		"microsoft-user-attribute-mapper", "oidc-advanced-group-idp-mapper",
		"oidc-advanced-role-idp-mapper", "oidc-hardcoded-group-idp-mapper",
		"oidc-hardcoded-role-idp-mapper", "oidc-role-idp-mapper", "oidc-user-attribute-idp-mapper",
		"oidc-user-session-note-idp-mapper", "oidc-username-idp-mapper",
		"openshift-v4-user-attribute-mapper", "paypal-user-attribute-mapper",
		"saml-advanced-group-idp-mapper", "saml-advanced-role-idp-mapper", "saml-role-idp-mapper",
		"saml-user-attribute-idp-mapper", "saml-username-idp-mapper",
		"saml-xpath-attribute-idp-mapper", "stackoverflow-user-attribute-mapper",
	},
}
