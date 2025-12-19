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
