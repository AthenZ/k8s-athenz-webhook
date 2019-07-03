module github.com/yahoo/k8s-athenz-webhook

go 1.12

require (
	github.com/ardielle/ardielle-go v1.5.2
	github.com/stretchr/testify v1.3.0
	github.com/yahoo/athenz v1.8.24
	github.com/yahoo/k8s-athenz-istio-auth v0.0.0-20190627022331-b77da8249656
	k8s.io/api release-1.13
	k8s.io/apimachinery release-1.13
	k8s.io/client-go v10.0.0
	sigs.k8s.io/yaml v1.1.0 // indirect
)
