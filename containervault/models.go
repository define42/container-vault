package main

import "time"

const sessionTTL = 30 * time.Minute

type sessionData struct {
	User       *User
	Access     []Access
	Namespaces []string
	CreatedAt  time.Time
}

type User struct {
	Name          string
	Group         string
	Namespace     string
	PullOnly      bool
	DeleteAllowed bool
}

type Access struct {
	Group         string
	Namespace     string
	PullOnly      bool
	DeleteAllowed bool
}

type LDAPConfig struct {
	URL             string
	BaseDN          string
	UserFilter      string
	GroupAttribute  string
	GroupNamePrefix string
	UserMailDomain  string
	StartTLS        bool
	SkipTLSVerify   bool
}

type repoInfo struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

type catalogResponse struct {
	Repositories []string `json:"repositories"`
}

type tagsResponse struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

type tagInfo struct {
	Tag            string `json:"tag"`
	Digest         string `json:"digest"`
	CompressedSize int64  `json:"compressed_size"`
}

type layerInfo struct {
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	MediaType string `json:"media_type"`
}

type platformInfo struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
}

type configInfo struct {
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	MediaType    string            `json:"media_type"`
	Created      string            `json:"created"`
	OS           string            `json:"os"`
	Architecture string            `json:"architecture"`
	Entrypoint   []string          `json:"entrypoint"`
	Cmd          []string          `json:"cmd"`
	Env          []string          `json:"env"`
	Labels       map[string]string `json:"labels"`
	HistoryCount int               `json:"history_count"`
	History      []historyInfo     `json:"history"`
}

type tagDetails struct {
	Repo          string         `json:"repo"`
	Tag           string         `json:"tag"`
	Digest        string         `json:"digest"`
	MediaType     string         `json:"media_type"`
	SchemaVersion int            `json:"schema_version"`
	Config        configInfo     `json:"config"`
	Platforms     []platformInfo `json:"platforms,omitempty"`
	Layers        []layerInfo    `json:"layers"`
}

type historyInfo struct {
	CreatedBy  string `json:"created_by"`
	EmptyLayer bool   `json:"empty_layer,omitempty"`
}
