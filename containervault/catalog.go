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
