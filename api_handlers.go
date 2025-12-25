package main

import (
	"context"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
)

type sessionContextKey struct{}

func registerAPI(api huma.API) {
	group := huma.NewGroup(api, "/api")
	group.UseMiddleware(sessionMiddleware(api))

	huma.Get(group, "/dashboard", handleDashboard)
	huma.Get(group, "/catalog", handleCatalog)
	huma.Get(group, "/repos", handleRepos)
	huma.Get(group, "/tags", handleTags)
	huma.Get(group, "/taginfo", handleTagInfo)
	huma.Get(group, "/taglayers", handleTagLayers)
	huma.Delete(group, "/tag", handleTagDelete)
}

func mustSession(ctx context.Context) sessionData {
	return ctx.Value(sessionContextKey{}).(sessionData)
}

func sessionMiddleware(api huma.API) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		req, _ := humachi.Unwrap(ctx)

		sess, ok := getSession(req)
		if !ok || sess.User == nil {
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "unauthorized")
			return
		}

		next(huma.WithValue(ctx, sessionContextKey{}, sess))
	}
}

type dashboardOutput struct {
	CacheControl string `header:"Cache-Control"`
	Pragma       string `header:"Pragma"`
	Expires      string `header:"Expires"`
	ContentType  string `header:"Content-Type"`
	Body         []byte
}

func handleDashboard(ctx context.Context, _ *struct{}) (*dashboardOutput, error) {
	sess := mustSession(ctx)

	page, err := renderDashboardHTML(sess)
	if err != nil {
		return nil, huma.Error500InternalServerError("unable to render dashboard")
	}

	return &dashboardOutput{
		CacheControl: cacheControlValue,
		Pragma:       pragmaValue,
		Expires:      expiresValue,
		ContentType:  "text/html; charset=utf-8",
		Body:         page,
	}, nil
}

func requireNamespace(sess sessionData, namespace string) (string, error) {
	ns := strings.TrimSpace(namespace)
	if ns == "" || !namespaceAllowed(sess.Namespaces, ns) {
		return "", huma.Error403Forbidden("namespace not allowed")
	}
	return ns, nil
}

func namespaceFromRepo(repo string) (string, error) {
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) < 2 {
		return "", huma.Error400BadRequest("invalid repo")
	}
	return parts[0], nil
}

func repoNamespace(repoInput string) (string, string, error) {
	repo := strings.TrimSpace(repoInput)
	if repo == "" {
		return "", "", huma.Error400BadRequest("missing repo")
	}
	namespace, err := namespaceFromRepo(repo)
	if err != nil {
		return "", "", err
	}
	return repo, namespace, nil
}

func repoTagNamespace(repoInput, tagInput string) (string, string, string, error) {
	repo := strings.TrimSpace(repoInput)
	tag := strings.TrimSpace(tagInput)
	if repo == "" || tag == "" {
		return "", "", "", huma.Error400BadRequest("missing repo or tag")
	}
	namespace, err := namespaceFromRepo(repo)
	if err != nil {
		return "", "", "", err
	}
	return repo, tag, namespace, nil
}

type catalogInput struct {
	Namespace string `query:"namespace"`
}

type catalogPayload struct {
	Username     string     `json:"username"`
	Namespace    string     `json:"namespace"`
	Repositories []repoInfo `json:"repositories"`
}

type catalogOutput struct {
	Body catalogPayload
}

func handleCatalog(ctx context.Context, input *catalogInput) (*catalogOutput, error) {
	sess := mustSession(ctx)

	namespace, err := requireNamespace(sess, input.Namespace)
	if err != nil {
		return nil, err
	}

	repos, err := fetchCatalog(ctx, namespace)
	if err != nil {
		return nil, huma.Error502BadGateway("registry unavailable")
	}

	return &catalogOutput{
		Body: catalogPayload{
			Username:     sess.User.Name,
			Namespace:    namespace,
			Repositories: repos,
		},
	}, nil
}

type reposInput struct {
	Namespace string `query:"namespace"`
}

type reposResponse struct {
	Namespace    string   `json:"namespace"`
	Repositories []string `json:"repositories"`
}

type reposOutput struct {
	Body reposResponse
}

func handleRepos(ctx context.Context, input *reposInput) (*reposOutput, error) {
	sess := mustSession(ctx)

	namespace, err := requireNamespace(sess, input.Namespace)
	if err != nil {
		return nil, err
	}

	repos, err := fetchRepos(ctx, namespace)
	if err != nil {
		return nil, huma.Error502BadGateway("registry unavailable")
	}

	return &reposOutput{
		Body: reposResponse{
			Namespace:    namespace,
			Repositories: repos,
		},
	}, nil
}

type tagsInput struct {
	Repo string `query:"repo"`
}

type tagsPayload struct {
	Repo string   `json:"repo"`
	Tags []string `json:"tags"`
}

type tagsOutput struct {
	Body tagsPayload
}

func handleTags(ctx context.Context, input *tagsInput) (*tagsOutput, error) {
	sess := mustSession(ctx)

	repo, namespace, err := repoNamespace(input.Repo)
	if err != nil {
		return nil, err
	}
	if !namespaceAllowed(sess.Namespaces, namespace) {
		return nil, huma.Error403Forbidden("namespace not allowed")
	}

	tags, err := fetchTags(ctx, repo)
	if err != nil {
		return nil, huma.Error502BadGateway("registry unavailable")
	}

	return &tagsOutput{
		Body: tagsPayload{
			Repo: repo,
			Tags: tags,
		},
	}, nil
}

type tagInfoInput struct {
	Repo string `query:"repo"`
	Tag  string `query:"tag"`
}

type tagInfoOutput struct {
	Body tagInfo
}

func handleTagInfo(ctx context.Context, input *tagInfoInput) (*tagInfoOutput, error) {
	sess := mustSession(ctx)

	repo, tag, namespace, err := repoTagNamespace(input.Repo, input.Tag)
	if err != nil {
		return nil, err
	}
	if !namespaceAllowed(sess.Namespaces, namespace) {
		return nil, huma.Error403Forbidden("namespace not allowed")
	}

	info, err := fetchTagInfo(ctx, repo, tag)
	if err != nil {
		return nil, huma.Error502BadGateway("registry unavailable")
	}

	return &tagInfoOutput{Body: info}, nil
}

type tagLayersInput struct {
	Repo string `query:"repo"`
	Tag  string `query:"tag"`
}

type tagLayersOutput struct {
	Body tagDetails
}

func handleTagLayers(ctx context.Context, input *tagLayersInput) (*tagLayersOutput, error) {
	sess := mustSession(ctx)

	repo, tag, namespace, err := repoTagNamespace(input.Repo, input.Tag)
	if err != nil {
		return nil, err
	}
	if !namespaceAllowed(sess.Namespaces, namespace) {
		return nil, huma.Error403Forbidden("namespace not allowed")
	}

	details, err := fetchTagDetails(ctx, repo, tag)
	if err != nil {
		return nil, huma.Error502BadGateway("registry unavailable")
	}

	return &tagLayersOutput{Body: details}, nil
}

type tagDeleteInput struct {
	Repo string `query:"repo"`
	Tag  string `query:"tag"`
}

type tagDeletePayload struct {
	Repo string `json:"repo"`
	Tag  string `json:"tag"`
}

type tagDeleteOutput struct {
	Body tagDeletePayload
}

func handleTagDelete(ctx context.Context, input *tagDeleteInput) (*tagDeleteOutput, error) {
	sess := mustSession(ctx)

	repo, tag, namespace, err := repoTagNamespace(input.Repo, input.Tag)
	if err != nil {
		return nil, err
	}
	if !namespaceAllowed(sess.Namespaces, namespace) {
		return nil, huma.Error403Forbidden("namespace not allowed")
	}
	if !namespaceDeleteAllowed(sess.Access, namespace) {
		return nil, huma.Error403Forbidden("delete not allowed")
	}

	digest, err := fetchTagDigest(ctx, repo, tag)
	if err != nil {
		if regErr, ok := err.(registryError); ok {
			if regErr.Status == http.StatusNotFound {
				return nil, huma.Error404NotFound("tag not found")
			}
			if regErr.Status == http.StatusMethodNotAllowed {
				return nil, huma.Error405MethodNotAllowed("registry tag lookup not allowed")
			}
		}
		return nil, huma.Error502BadGateway("registry unavailable")
	}
	if digest == "" {
		return nil, huma.Error502BadGateway("manifest digest missing")
	}

	if err := deleteManifest(ctx, repo, digest); err != nil {
		if regErr, ok := err.(registryError); ok {
			if regErr.Status == http.StatusNotFound {
				return nil, huma.Error404NotFound("tag not found")
			}
			if regErr.Status == http.StatusMethodNotAllowed {
				return nil, huma.Error405MethodNotAllowed("registry delete disabled")
			}
		}
		return nil, huma.Error502BadGateway("registry delete failed")
	}

	return &tagDeleteOutput{
		Body: tagDeletePayload{
			Repo: repo,
			Tag:  tag,
		},
	}, nil
}
