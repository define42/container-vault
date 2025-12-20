package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func fetchCatalog(ctx context.Context, namespace string) ([]repoInfo, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	catalogURL := upstream.ResolveReference(&url.URL{Path: "/v2/_catalog"})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, catalogURL.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("catalog status: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var cat catalogResponse
	if err := json.Unmarshal(body, &cat); err != nil {
		return nil, err
	}

	var repos []repoInfo
	prefix := namespace + "/"
	for _, repo := range cat.Repositories {
		if !strings.HasPrefix(repo, prefix) {
			continue
		}
		tagsURL := upstream.ResolveReference(&url.URL{Path: "/v2/" + repo + "/tags/list"})
		tagReq, err := http.NewRequestWithContext(ctx, http.MethodGet, tagsURL.String(), nil)
		if err != nil {
			return nil, err
		}
		tagResp, err := client.Do(tagReq)
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(tagResp.Body)
		tagResp.Body.Close()
		if err != nil {
			return nil, err
		}
		if tagResp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("tags status: %s", tagResp.Status)
		}
		var tags tagsResponse
		if err := json.Unmarshal(data, &tags); err != nil {
			return nil, err
		}
		repos = append(repos, repoInfo{Name: repo, Tags: tags.Tags})
	}

	return repos, nil
}

func fetchRepos(ctx context.Context, namespace string) ([]string, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	catalogURL := upstream.ResolveReference(&url.URL{Path: "/v2/_catalog"})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, catalogURL.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("catalog status: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var cat catalogResponse
	if err := json.Unmarshal(body, &cat); err != nil {
		return nil, err
	}

	var repos []string
	prefix := namespace + "/"
	for _, repo := range cat.Repositories {
		if strings.HasPrefix(repo, prefix) {
			repos = append(repos, repo)
		}
	}
	return repos, nil
}

func fetchTags(ctx context.Context, repo string) ([]string, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	tagsURL := upstream.ResolveReference(&url.URL{Path: "/v2/" + repo + "/tags/list"})
	tagReq, err := http.NewRequestWithContext(ctx, http.MethodGet, tagsURL.String(), nil)
	if err != nil {
		return nil, err
	}
	tagResp, err := client.Do(tagReq)
	if err != nil {
		return nil, err
	}
	defer tagResp.Body.Close()
	if tagResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tags status: %s", tagResp.Status)
	}
	data, err := io.ReadAll(tagResp.Body)
	if err != nil {
		return nil, err
	}
	var tags tagsResponse
	if err := json.Unmarshal(data, &tags); err != nil {
		return nil, err
	}
	return tags.Tags, nil
}

func fetchTagInfo(ctx context.Context, repo, tag string) (tagInfo, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	manifestURL := upstream.ResolveReference(&url.URL{Path: "/v2/" + repo + "/manifests/" + tag})

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL.String(), nil)
	if err != nil {
		return tagInfo{}, err
	}
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.oci.image.index.v1+json",
	}, ", "))

	resp, err := client.Do(req)
	if err != nil {
		return tagInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return tagInfo{}, fmt.Errorf("manifest status: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return tagInfo{}, err
	}

	digest := resp.Header.Get("Docker-Content-Digest")
	compressed, err := manifestCompressedSize(ctx, client, repo, body, resp.Header.Get("Content-Type"))
	if err != nil {
		return tagInfo{}, err
	}

	return tagInfo{
		Tag:            tag,
		Digest:         digest,
		CompressedSize: compressed,
	}, nil
}

type manifestSchema2 struct {
	SchemaVersion int    `json:"schemaVersion"`
	MediaType     string `json:"mediaType"`
	Config        struct {
		Size      int64  `json:"size"`
		Digest    string `json:"digest"`
		MediaType string `json:"mediaType"`
	} `json:"config"`
	Layers []struct {
		Size      int64  `json:"size"`
		Digest    string `json:"digest"`
		MediaType string `json:"mediaType"`
	} `json:"layers"`
}

type manifestList struct {
	SchemaVersion int    `json:"schemaVersion"`
	MediaType     string `json:"mediaType"`
	Manifests     []struct {
		Digest   string `json:"digest"`
		Size     int64  `json:"size"`
		Platform struct {
			Architecture string `json:"architecture"`
			OS           string `json:"os"`
			Variant      string `json:"variant"`
		} `json:"platform"`
	} `json:"manifests"`
}

func manifestCompressedSize(ctx context.Context, client *http.Client, repo string, payload []byte, contentType string) (int64, error) {
	if strings.Contains(contentType, "manifest.list") || strings.Contains(contentType, "image.index") {
		var list manifestList
		if err := json.Unmarshal(payload, &list); err != nil {
			return 0, err
		}
		selected := ""
		for _, manifest := range list.Manifests {
			if manifest.Platform.OS == "linux" && manifest.Platform.Architecture == "amd64" {
				selected = manifest.Digest
				break
			}
		}
		if selected == "" && len(list.Manifests) > 0 {
			selected = list.Manifests[0].Digest
		}
		if selected == "" {
			return 0, fmt.Errorf("manifest list empty")
		}
		return fetchManifestCompressedSizeByDigest(ctx, client, repo, selected)
	}

	var manifest manifestSchema2
	if err := json.Unmarshal(payload, &manifest); err != nil {
		return 0, err
	}
	var compressed int64
	compressed += manifest.Config.Size
	for _, layer := range manifest.Layers {
		compressed += layer.Size
	}
	return compressed, nil
}

func fetchManifestCompressedSizeByDigest(ctx context.Context, client *http.Client, repo, digest string) (int64, error) {
	manifestURL := upstream.ResolveReference(&url.URL{Path: "/v2/" + repo + "/manifests/" + digest})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL.String(), nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
	}, ", "))
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("manifest status: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	var manifest manifestSchema2
	if err := json.Unmarshal(body, &manifest); err != nil {
		return 0, err
	}
	var compressed int64
	compressed += manifest.Config.Size
	for _, layer := range manifest.Layers {
		compressed += layer.Size
	}
	return compressed, nil
}

type imageConfig struct {
	Created      string `json:"created"`
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Config       struct {
		Entrypoint []string          `json:"Entrypoint"`
		Cmd        []string          `json:"Cmd"`
		Env        []string          `json:"Env"`
		Labels     map[string]string `json:"Labels"`
	} `json:"config"`
	History []struct {
		CreatedBy  string `json:"created_by"`
		EmptyLayer bool   `json:"empty_layer"`
	} `json:"history"`
}

func fetchTagDetails(ctx context.Context, repo, tag string) (tagDetails, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	manifestURL := upstream.ResolveReference(&url.URL{Path: "/v2/" + repo + "/manifests/" + tag})

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL.String(), nil)
	if err != nil {
		return tagDetails{}, err
	}
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.oci.image.index.v1+json",
	}, ", "))

	resp, err := client.Do(req)
	if err != nil {
		return tagDetails{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return tagDetails{}, fmt.Errorf("manifest status: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return tagDetails{}, err
	}

	manifestBody := body
	contentType := resp.Header.Get("Content-Type")
	digest := resp.Header.Get("Docker-Content-Digest")
	details := tagDetails{
		Repo:      repo,
		Tag:       tag,
		Digest:    digest,
		MediaType: contentType,
	}

	if strings.Contains(contentType, "manifest.list") || strings.Contains(contentType, "image.index") {
		var list manifestList
		if err := json.Unmarshal(body, &list); err != nil {
			return tagDetails{}, err
		}
		details.Platforms = make([]platformInfo, 0, len(list.Manifests))
		for _, manifest := range list.Manifests {
			details.Platforms = append(details.Platforms, platformInfo{
				OS:           manifest.Platform.OS,
				Architecture: manifest.Platform.Architecture,
				Variant:      manifest.Platform.Variant,
			})
		}
		selected := ""
		for _, manifest := range list.Manifests {
			if manifest.Platform.OS == "linux" && manifest.Platform.Architecture == "amd64" {
				selected = manifest.Digest
				break
			}
		}
		if selected == "" && len(list.Manifests) > 0 {
			selected = list.Manifests[0].Digest
		}
		if selected == "" {
			return tagDetails{}, fmt.Errorf("manifest list empty")
		}
		manifestBody, err = fetchManifestByDigest(ctx, client, repo, selected)
		if err != nil {
			return tagDetails{}, err
		}
	}

	var manifest manifestSchema2
	if err := json.Unmarshal(manifestBody, &manifest); err != nil {
		return tagDetails{}, err
	}

	details.SchemaVersion = manifest.SchemaVersion
	if manifest.MediaType != "" {
		details.MediaType = manifest.MediaType
	}

	layers := make([]layerInfo, 0, len(manifest.Layers))
	for _, layer := range manifest.Layers {
		layers = append(layers, layerInfo{
			Digest:    layer.Digest,
			Size:      layer.Size,
			MediaType: layer.MediaType,
		})
	}
	details.Layers = layers

	config, err := fetchConfigInfo(ctx, client, repo, manifest)
	if err != nil {
		return tagDetails{}, err
	}
	details.Config = config
	return details, nil
}

func fetchManifestByDigest(ctx context.Context, client *http.Client, repo, digest string) ([]byte, error) {
	manifestURL := upstream.ResolveReference(&url.URL{Path: "/v2/" + repo + "/manifests/" + digest})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
	}, ", "))
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest status: %s", resp.Status)
	}
	return io.ReadAll(resp.Body)
}

func fetchConfigInfo(ctx context.Context, client *http.Client, repo string, manifest manifestSchema2) (configInfo, error) {
	info := configInfo{
		Digest:    manifest.Config.Digest,
		Size:      manifest.Config.Size,
		MediaType: manifest.Config.MediaType,
	}
	if manifest.Config.Digest == "" {
		return info, nil
	}
	blobURL := upstream.ResolveReference(&url.URL{Path: "/v2/" + repo + "/blobs/" + manifest.Config.Digest})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, blobURL.String(), nil)
	if err != nil {
		return info, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return info, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return info, fmt.Errorf("config blob status: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return info, err
	}
	var cfg imageConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return info, err
	}
	info.Created = cfg.Created
	info.OS = cfg.OS
	info.Architecture = cfg.Architecture
	info.Entrypoint = cfg.Config.Entrypoint
	info.Cmd = cfg.Config.Cmd
	info.Env = cfg.Config.Env
	info.Labels = cfg.Config.Labels
	info.HistoryCount = len(cfg.History)
	if len(cfg.History) > 0 {
		info.History = make([]historyInfo, 0, len(cfg.History))
		for _, entry := range cfg.History {
			info.History = append(info.History, historyInfo{
				CreatedBy:  entry.CreatedBy,
				EmptyLayer: entry.EmptyLayer,
			})
		}
	}
	return info, nil
}
