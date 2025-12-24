all:
	docker compose build


lint:
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@latest run
gosec:
	go run github.com/securego/gosec/v2/cmd/gosec@latest ./...
test:
	go test 
run:
	docker compose down
	docker compose build
	docker compose up -d
	google-chrome --no-sandbox --ignore-certificate-errors --disable-application-cache   --disk-cache-size=1  --media-cache-size=1  --user-data-dir=/tmp/chrome-nocache --no-first-run --no-default-browser-check https://localhost

delete:
	skopeo delete   --creds alice:secretpassword   --tls-verify=false   docker://skod.net/team1/registry:2
cover:
	go test ./... -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html
	firefox coverage.html
ldaptest:
	DAPTLS_REQCERT=never ldapsearch -x   -H ldaps://localhost:389 -D "cn=johndoe,ou=,ou=users,dc=glauth,dc=com" -w dogood -b  "dc=glauth,dc=com" "(cn=johndoe)"

