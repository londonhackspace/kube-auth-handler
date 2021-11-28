module github.com/londonhackspace/kube-auth-handler

go 1.16

require (
	github.com/go-ldap/ldap/v3 v3.4.1
	github.com/go-redis/redis/v8 v8.11.4
	github.com/gorilla/mux v1.8.0
	github.com/rs/zerolog v1.26.0
	golang.org/x/term v0.0.0-20210220032956-6a3ed077a48d
	k8s.io/api v0.22.4
	k8s.io/apimachinery v0.22.4
	k8s.io/client-go v0.22.4
)
