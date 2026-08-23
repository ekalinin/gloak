//go:build docker

package admin

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestKcadmDrivesTheAdminAPI runs Keycloak's own admin CLI against Gloak.
//
// # What this proves, and what it does not
//
// The conformance suite compares Gloak's bytes with bytes recorded from a
// live Keycloak. It can only compare what a case asks for. `kcadm.sh` asks
// for things no case does: it authenticates the way it chooses, sends the
// fields it chooses, and reads back what it chooses. That is the whole value
// - it found the missing `description` field on ClientRepresentation within a
// minute of first running, because no bootstrapped client has one and so no
// golden had ever covered it.
//
// It is a **narrow** oracle today and the narrowness is deliberate. kcadm
// normally starts by creating a realm, which is P4, so this authenticates
// against `master` directly and stays inside create, read, update and delete
// on a client and on a user, plus the password and logout operations P2
// serves. It becomes a real oracle after P4 and P5, when kcadm's own workflows
// stop needing endpoints Gloak has not built.
//
// It runs behind the docker tag: `make test` must never need Docker.
func TestKcadmDrivesTheAdminAPI(t *testing.T) {
	// Gloak listens on a real socket rather than through httptest's default,
	// because the client is in a container and has to reach it by address.
	h, _, _ := newServer(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &httptest.Server{
		Listener: listener,
		Config:   &http.Server{Handler: h},
	}
	server.Start()
	t.Cleanup(server.Close)

	port := listener.Addr().(*net.TCPAddr).Port
	// host-gateway is how a container reaches a listener on the host. The
	// address Gloak was bootstrapped with does not match, and that is fine:
	// nothing here reads an issuer out of a token.
	base := fmt.Sprintf("http://host.docker.internal:%d", port)

	script := strings.Join([]string{
		"set -e",
		"K=/opt/keycloak/bin/kcadm.sh",
		"$K config credentials --server " + base + " --realm master --user admin --password admin",

		// A client through its whole life.
		"CID=$($K create clients -r master -s clientId=kcadm-client -s enabled=true" +
			" -s 'description=set by kcadm' -i)",
		"$K get clients/$CID -r master --fields clientId,description | grep -q 'set by kcadm'",
		"$K update clients/$CID -r master -s 'description=changed by kcadm'",
		"$K get clients/$CID -r master --fields description | grep -q 'changed by kcadm'",
		"$K get clients/$CID/client-secret -r master | grep -q '\"type\" : \"secret\"'",
		"$K delete clients/$CID -r master",

		// A user through its whole life, including a password and a logout.
		"UID2=$($K create users -r master -s username=kcadm-user -s enabled=true -i)",
		"$K get users/$UID2 -r master --fields username | grep -q kcadm-user",
		"$K update users/$UID2 -r master -s firstName=Ada",
		"$K get users -r master -q username=kcadm-user --fields firstName | grep -q Ada",
		"$K set-password -r master --userid $UID2 --new-password s3cret",
		"$K get users/$UID2/credentials -r master | grep -q '\"type\" : \"password\"'",
		"$K create users/$UID2/logout -r master",
		"$K delete users/$UID2 -r master",

		// And the listing it started with still works after all of that.
		"$K get clients -r master --fields clientId | grep -q admin-cli",
	}, "\n")

	out, err := runKcadm(t, script)
	if err != nil {
		t.Fatalf("kcadm.sh could not drive Gloak: %v\n%s", err, out)
	}
}

// runKcadm executes a script inside the Keycloak image, which ships kcadm.sh,
// so nothing has to be installed on the machine running the tests.
//
// It shells out to the docker CLI rather than using testcontainers, because
// the container needs a host-gateway entry and lives for one command. A
// testcontainers container would be more machinery for less.
func runKcadm(t *testing.T, script string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not on PATH")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "run", "--rm",
		"--entrypoint", "/bin/bash",
		"--add-host=host.docker.internal:host-gateway",
		keycloakImage, "-c", script)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// keycloakImage is the pinned compatibility target, the same tag the
// conformance recorder uses. Drifting it here would mean testing against a
// client from one version and a contract from another.
const keycloakImage = "quay.io/keycloak/keycloak:26.7.1"
