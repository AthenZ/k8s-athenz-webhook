# k8s-athenz-webhook

[![GoDoc](https://godoc.org/github.com/yahoo/k8s-athenz-webhook?status.svg)](https://godoc.org/github.com/yahoo/k8s-athenz-webhook)
[![Build Status](https://travis-ci.org/yahoo/k8s-athenz-webhook.svg?branch=master)](https://travis-ci.org/yahoo/k8s-athenz-webhook)
[![Coverage Status](https://coveralls.io/repos/github/yahoo/k8s-athenz-webhook/badge.svg?branch=master)](https://coveralls.io/github/yahoo/k8s-athenz-webhook?branch=master)

API for a Kubernetes authentication and authorization webhook that integrates with
[Athenz](https://github.com/yahoo/athenz) for access checks. It allows flexible resource
mapping from K8s resources to Athenz ones.

This repo does not provide a main program that you can run out of the box. See the
[example directory](example/auth-webhook) for a reference implementation that you can
customize to suit your needs.

You can also use just the authorization hook without also using the authentication hook.
Use of the authentication hook requires Athenz to be able to sign tokens for users.

Requires go 1.8 or better.

### Credits

[@jer](https://github.com/jer) is the original author of the code out of which the API was extracted.
