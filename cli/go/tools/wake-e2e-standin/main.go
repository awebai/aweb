// Command wake-e2e-standin is the server side of scripts/e2e-wake-broker.sh.
//
// It does two jobs the shell cannot do on its own:
//
//   - mints a real, certificate-authenticated identity home, so `aw wake run`
//     builds its client through the same selection path every other
//     identity-home-aware command uses. Nothing about authentication is faked.
//   - serves GET /v1/events/stream from a file the script appends to, and
//     records the path of every request it receives.
//
// The request log is what makes "the broker acknowledged nothing" checkable at
// the wire rather than by reading code: the script asserts the whole set of
// paths the server ever saw, so a future fetch or ack nobody thought to forbid
// still fails the run.
//
// It is a test harness. It verifies no signature and serves no real data.
package main

import (
	"bufio"
	"crypto/ed25519"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

const teamID = "runtime:aweb.test"

func main() {
	root := flag.String("root", "", "directory to mint the identity home and write control files into")
	alias := flag.String("alias", "probe", "member alias")
	flag.Parse()

	if strings.TrimSpace(*root) == "" {
		log.Fatal("--root is required")
	}
	absRoot, err := filepath.Abs(*root)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(absRoot, 0o700); err != nil {
		log.Fatal(err)
	}

	eventsPath := filepath.Join(absRoot, "events.jsonl")
	if err := os.WriteFile(eventsPath, nil, 0o600); err != nil {
		log.Fatal(err)
	}
	requestsPath := filepath.Join(absRoot, "requests.log")
	if err := os.WriteFile(requestsPath, nil, 0o600); err != nil {
		log.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	baseURL := "http://" + listener.Addr().String()

	identityDir := filepath.Join(absRoot, "instance")
	if err := mintIdentityHome(identityDir, baseURL, *alias); err != nil {
		log.Fatalf("mint identity home: %v", err)
	}

	var mu sync.Mutex
	record := func(r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		f, err := os.OpenFile(requestsPath, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return
		}
		defer f.Close()
		authed := "unauthenticated"
		if strings.TrimSpace(r.Header.Get("X-AWID-Team-Certificate")) != "" {
			authed = "certificate"
		}
		fmt.Fprintf(f, "%s %s %s\n", r.Method, r.URL.Path, authed)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		http.Error(w, "unexpected request", http.StatusNotFound)
	})
	// `aw` probes for aweb with GET /v1/agents/heartbeat on candidate bases.
	mux.HandleFunc("/v1/agents/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	mux.HandleFunc("/v1/events/stream", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		serveStream(w, r, eventsPath)
	})

	if err := os.WriteFile(filepath.Join(absRoot, "aweb-url"), []byte(baseURL+"\n"), 0o600); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(absRoot, "ready"), []byte("ready\n"), 0o600); err != nil {
		log.Fatal(err)
	}
	fmt.Println(baseURL)

	server := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	if err := server.Serve(listener); err != nil {
		log.Fatal(err)
	}
}

// serveStream emits every event in the file, then tails it.
//
// Emitting the whole file on every connection is the stand-in for the server's
// reconnect snapshot: an item the instance has not read is raised again by the
// next stream, which is the mechanism the broker relies on instead of a cursor,
// and the reason nothing durable in the broker may suppress it.
func serveStream(w http.ResponseWriter, r *http.Request, eventsPath string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)

	sent := 0
	ticker := time.NewTicker(150 * time.Millisecond)
	defer ticker.Stop()

	for {
		lines, err := readLines(eventsPath)
		if err == nil {
			for ; sent < len(lines); sent++ {
				line := strings.TrimSpace(lines[sent])
				if line == "" {
					continue
				}
				name, data, ok := strings.Cut(line, "\t")
				if !ok {
					continue
				}
				fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, data)
				if flusher != nil {
					flusher.Flush()
				}
			}
		}
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
	}
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// mintIdentityHome writes a workspace whose identity home at <dir>/.aw is
// certificate-authenticated against baseURL. The team key is generated here and
// thrown away: nothing verifies the certificate, but `aw` must be able to load
// and present one, and it is loaded through the real code path.
func mintIdentityHome(dir, baseURL, alias string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		return err
	}
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		return err
	}
	domain, _, err := awid.ParseTeamID(teamID)
	if err != nil {
		return err
	}
	address := domain + "/" + alias
	memberDID := awid.ComputeDIDKey(memberPub)

	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team:          teamID,
		MemberDIDKey:  memberDID,
		MemberAddress: address,
		Alias:         alias,
		IdentityScope: awid.IdentityModeLocal,
	})
	if err != nil {
		return err
	}
	if _, err := awconfig.SaveTeamCertificateForTeam(dir, teamID, cert); err != nil {
		return err
	}
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(dir), ed25519.PrivateKey(memberKey)); err != nil {
		return err
	}

	workspace := awconfig.WorktreeWorkspace{
		AwebURL: baseURL,
		Memberships: []awconfig.WorktreeMembership{{
			TeamID:      teamID,
			Alias:       alias,
			WorkspaceID: "workspace-" + alias,
			CertPath:    awconfig.TeamCertificateRelativePath(teamID),
			JoinedAt:    "2026-09-05T00:00:00Z",
		}},
		WorkspacePath: dir,
	}
	if err := awconfig.SaveWorktreeWorkspaceTo(filepath.Join(dir, awconfig.DefaultWorktreeWorkspaceRelativePath()), &workspace); err != nil {
		return err
	}
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(dir, awconfig.DefaultWorktreeIdentityRelativePath()), &awconfig.WorktreeIdentity{
		DID:           memberDID,
		Address:       address,
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeLocal,
		CreatedAt:     "2026-09-05T00:00:00Z",
	}); err != nil {
		return err
	}
	return awconfig.SaveTeamState(dir, &awconfig.TeamState{
		ActiveTeam: teamID,
		Memberships: []awconfig.TeamMembership{{
			TeamID:   teamID,
			Alias:    alias,
			CertPath: awconfig.TeamCertificateRelativePath(teamID),
			JoinedAt: "2026-09-05T00:00:00Z",
		}},
	})
}
