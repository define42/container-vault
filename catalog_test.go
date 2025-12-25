package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestFetchCatalogFiltersAndTags(t *testing.T) {
	cleanup := withUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/_catalog":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"repositories":["team1/app","team2/other","team1/edge"]}`))
		case "/v2/team1/app/tags/list":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"team1/app","tags":["v1","v2"]}`))
		case "/v2/team1/edge/tags/list":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"team1/edge","tags":["latest"]}`))
		default:
			http.NotFound(w, r)
		}
	})
	defer cleanup()

	repos, err := fetchCatalog(context.Background(), "team1")
	if err != nil {
		t.Fatalf("fetchCatalog: %v", err)
	}
	if len(repos) != 2 {
		t.Fatalf("expected 2 repos, got %d", len(repos))
	}
	if repos[0].Name != "team1/app" || !reflect.DeepEqual(repos[0].Tags, []string{"v1", "v2"}) {
		t.Fatalf("unexpected repo[0]: %#v", repos[0])
	}
	if repos[1].Name != "team1/edge" || !reflect.DeepEqual(repos[1].Tags, []string{"latest"}) {
		t.Fatalf("unexpected repo[1]: %#v", repos[1])
	}
}

func TestFetchCatalogStatusError(t *testing.T) {
	cleanup := withUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/_catalog" {
			http.Error(w, "nope", http.StatusServiceUnavailable)
			return
		}
		http.NotFound(w, r)
	})
	defer cleanup()

	_, err := fetchCatalog(context.Background(), "team1")
	if err == nil || !strings.Contains(err.Error(), "catalog status") {
		t.Fatalf("expected catalog status error, got %v", err)
	}
}

func TestFetchReposFilters(t *testing.T) {
	cleanup := withUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/_catalog" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"repositories":["team1/app","team2/other","team1/edge"]}`))
	})
	defer cleanup()

	repos, err := fetchRepos(context.Background(), "team1")
	if err != nil {
		t.Fatalf("fetchRepos: %v", err)
	}
	expected := []string{"team1/app", "team1/edge"}
	if !reflect.DeepEqual(repos, expected) {
		t.Fatalf("expected %v, got %v", expected, repos)
	}
}

func TestFetchTagsSuccess(t *testing.T) {
	cleanup := withUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/team1/app/tags/list" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"team1/app","tags":["v1","v2"]}`))
	})
	defer cleanup()

	tags, err := fetchTags(context.Background(), "team1/app")
	if err != nil {
		t.Fatalf("fetchTags: %v", err)
	}
	if !reflect.DeepEqual(tags, []string{"v1", "v2"}) {
		t.Fatalf("unexpected tags: %v", tags)
	}
}

func TestFetchTagsStatusError(t *testing.T) {
	cleanup := withUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no tags", http.StatusNotFound)
	})
	defer cleanup()

	_, err := fetchTags(context.Background(), "team1/app")
	if err == nil || !strings.Contains(err.Error(), "tags status") {
		t.Fatalf("expected tags status error, got %v", err)
	}
}

func TestFetchTagInfoSchema2(t *testing.T) {
	cleanup := withUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/team1/app/manifests/latest" {
			http.NotFound(w, r)
			return
		}
		if !strings.Contains(r.Header.Get("Accept"), "manifest.v2+json") {
			http.Error(w, "missing accept header", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		w.Header().Set("Docker-Content-Digest", "sha256:abc")
		_, _ = w.Write([]byte(`{
  "schemaVersion": 2,
  "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
  "config": { "size": 11, "digest": "sha256:cfg", "mediaType": "application/vnd.docker.container.image.v1+json" },
  "layers": [
    { "size": 5, "digest": "sha256:a", "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip" },
    { "size": 7, "digest": "sha256:b", "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip" }
  ]
}`))
	})
	defer cleanup()

	info, err := fetchTagInfo(context.Background(), "team1/app", "latest")
	if err != nil {
		t.Fatalf("fetchTagInfo: %v", err)
	}
	if info.Digest != "sha256:abc" || info.CompressedSize != 23 || info.Tag != "latest" {
		t.Fatalf("unexpected info: %#v", info)
	}
}

func TestFetchTagInfoManifestList(t *testing.T) {
	cleanup := withUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/team1/app/manifests/stable":
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.list.v2+json")
			w.Header().Set("Docker-Content-Digest", "sha256:list")
			_, _ = w.Write([]byte(`{
  "schemaVersion": 2,
  "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
  "manifests": [
    { "digest": "sha256:linux", "size": 111, "platform": { "os": "linux", "architecture": "amd64" } },
    { "digest": "sha256:arm", "size": 222, "platform": { "os": "linux", "architecture": "arm64" } }
  ]
}`))
		case "/v2/team1/app/manifests/sha256:linux":
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			_, _ = w.Write([]byte(`{
  "schemaVersion": 2,
  "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
  "config": { "size": 3, "digest": "sha256:cfg", "mediaType": "application/vnd.docker.container.image.v1+json" },
  "layers": [
    { "size": 4, "digest": "sha256:a", "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip" }
  ]
}`))
		default:
			http.NotFound(w, r)
		}
	})
	defer cleanup()

	info, err := fetchTagInfo(context.Background(), "team1/app", "stable")
	if err != nil {
		t.Fatalf("fetchTagInfo: %v", err)
	}
	if info.Digest != "sha256:list" || info.CompressedSize != 7 || info.Tag != "stable" {
		t.Fatalf("unexpected info: %#v", info)
	}
}

func TestFetchManifestByDigest(t *testing.T) {
	client := &http.Client{}
	cleanup := withUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/team1/app/manifests/sha256:abc" {
			http.NotFound(w, r)
			return
		}
		if !strings.Contains(r.Header.Get("Accept"), "manifest.v2+json") {
			http.Error(w, "missing accept header", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		_, _ = w.Write([]byte(`{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json"}`))
	})
	defer cleanup()

	body, err := fetchManifestByDigest(context.Background(), client, "team1/app", "sha256:abc")
	if err != nil {
		t.Fatalf("fetchManifestByDigest: %v", err)
	}
	if !strings.Contains(string(body), `"schemaVersion":2`) {
		t.Fatalf("unexpected manifest body: %s", string(body))
	}
}

func TestFetchManifestByDigestStatusError(t *testing.T) {
	client := &http.Client{}
	cleanup := withUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "missing", http.StatusNotFound)
	})
	defer cleanup()

	_, err := fetchManifestByDigest(context.Background(), client, "team1/app", "sha256:missing")
	if err == nil || !strings.Contains(err.Error(), "manifest status") {
		t.Fatalf("expected manifest status error, got %v", err)
	}
}

func TestFetchConfigInfo(t *testing.T) {
	client := &http.Client{}
	cleanup := withUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/team1/app/blobs/sha256:cfg" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "created": "2024-01-01T00:00:00Z",
  "os": "linux",
  "architecture": "amd64",
  "config": {
    "Entrypoint": ["/bin/sh"],
    "Cmd": ["-c", "echo hello"],
    "Env": ["A=1"],
    "Labels": {"org.test":"value"}
  },
  "history": [
    {"created_by": "/bin/sh -c echo hello", "empty_layer": false}
  ]
}`))
	})
	defer cleanup()

	manifest := manifestSchema2{
		SchemaVersion: 2,
		MediaType:     "application/vnd.docker.distribution.manifest.v2+json",
	}
	manifest.Config.Digest = "sha256:cfg"
	manifest.Config.Size = 42
	manifest.Config.MediaType = "application/vnd.docker.container.image.v1+json"

	info, err := fetchConfigInfo(context.Background(), client, "team1/app", manifest)
	if err != nil {
		t.Fatalf("fetchConfigInfo: %v", err)
	}
	if info.Digest != "sha256:cfg" || info.Size != 42 || info.OS != "linux" || info.Architecture != "amd64" {
		t.Fatalf("unexpected config info: %#v", info)
	}
	if info.HistoryCount != 1 || len(info.History) != 1 {
		t.Fatalf("unexpected history info: %#v", info.History)
	}
	if len(info.Entrypoint) != 1 || info.Entrypoint[0] != "/bin/sh" {
		t.Fatalf("unexpected entrypoint: %#v", info.Entrypoint)
	}
}

func TestFetchTagDetailsSchema2(t *testing.T) {
	cleanup := withUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/team1/app/manifests/latest":
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			w.Header().Set("Docker-Content-Digest", "sha256:manifest")
			_, _ = w.Write([]byte(`{
  "schemaVersion": 2,
  "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
  "config": { "size": 12, "digest": "sha256:cfg", "mediaType": "application/vnd.docker.container.image.v1+json" },
  "layers": [
    { "size": 5, "digest": "sha256:a", "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip" }
  ]
}`))
		case "/v2/team1/app/blobs/sha256:cfg":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"created":"2024-01-01T00:00:00Z","os":"linux","architecture":"amd64","config":{"Entrypoint":[],"Cmd":[],"Env":[],"Labels":{}},"history":[]}`))
		default:
			http.NotFound(w, r)
		}
	})
	defer cleanup()

	details, err := fetchTagDetails(context.Background(), "team1/app", "latest")
	if err != nil {
		t.Fatalf("fetchTagDetails: %v", err)
	}
	if details.Digest != "sha256:manifest" || details.SchemaVersion != 2 || details.Tag != "latest" {
		t.Fatalf("unexpected details: %#v", details)
	}
	if len(details.Layers) != 1 || details.Layers[0].Digest != "sha256:a" {
		t.Fatalf("unexpected layers: %#v", details.Layers)
	}
	if details.Config.Digest != "sha256:cfg" || details.Config.OS != "linux" {
		t.Fatalf("unexpected config: %#v", details.Config)
	}
}

func TestFetchTagDetailsManifestList(t *testing.T) {
	cleanup := withUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/team1/app/manifests/stable":
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.list.v2+json")
			w.Header().Set("Docker-Content-Digest", "sha256:list")
			_, _ = w.Write([]byte(`{
  "schemaVersion": 2,
  "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
  "manifests": [
    { "digest": "sha256:linux", "size": 111, "platform": { "os": "linux", "architecture": "amd64" } },
    { "digest": "sha256:arm", "size": 222, "platform": { "os": "linux", "architecture": "arm64" } }
  ]
}`))
		case "/v2/team1/app/manifests/sha256:linux":
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			_, _ = w.Write([]byte(`{
  "schemaVersion": 2,
  "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
  "config": { "size": 2, "digest": "sha256:cfg", "mediaType": "application/vnd.docker.container.image.v1+json" },
  "layers": [
    { "size": 4, "digest": "sha256:a", "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip" }
  ]
}`))
		case "/v2/team1/app/blobs/sha256:cfg":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"created":"2024-01-02T00:00:00Z","os":"linux","architecture":"amd64","config":{"Entrypoint":[],"Cmd":[],"Env":[],"Labels":{}},"history":[]}`))
		default:
			http.NotFound(w, r)
		}
	})
	defer cleanup()

	details, err := fetchTagDetails(context.Background(), "team1/app", "stable")
	if err != nil {
		t.Fatalf("fetchTagDetails: %v", err)
	}
	if details.Digest != "sha256:list" || details.SchemaVersion != 2 {
		t.Fatalf("unexpected details: %#v", details)
	}
	if len(details.Platforms) != 2 || details.Platforms[0].OS != "linux" {
		t.Fatalf("unexpected platforms: %#v", details.Platforms)
	}
	if details.Config.Digest != "sha256:cfg" || len(details.Layers) != 1 {
		t.Fatalf("unexpected config/layers: %#v %#v", details.Config, details.Layers)
	}
}

func TestDeleteManifestNotFound(t *testing.T) {
	cleanup := withUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/v2/team1/app/manifests/sha256:missing" {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "manifest not found", http.StatusNotFound)
	})
	defer cleanup()

	status, message, err := deleteManifest(context.Background(), "team1/app", "sha256:missing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d", http.StatusNotFound, status)
	}
	if message != "manifest not found" {
		t.Fatalf("expected message %q, got %q", "manifest not found", message)
	}
}

func TestDeleteManifestMethodNotAllowed(t *testing.T) {
	cleanup := withUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/v2/team1/app/manifests/sha256:locked" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	defer cleanup()

	status, message, err := deleteManifest(context.Background(), "team1/app", "sha256:locked")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, status)
	}
	if message != "405 Method Not Allowed" {
		t.Fatalf("expected message %q, got %q", "405 Method Not Allowed", message)
	}
}

func withUpstream(t *testing.T, handler http.HandlerFunc) func() {
	t.Helper()
	server := httptest.NewServer(handler)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		server.Close()
		t.Fatalf("parse server url: %v", err)
	}
	prev := upstream
	upstream = parsed
	return func() {
		upstream = prev
		server.Close()
	}
}
