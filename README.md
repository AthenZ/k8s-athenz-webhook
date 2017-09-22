# k8s-athenz-auth

API for an Kubernetes authentication and authorization webhook that integrates with
[Athenz](https://github.com/yahoo/athenz) for access checks. It allows flexible resource
mapping from K8s resources to Athenz ones.

This repo does not provide a main program that you can run out of the box. See the
[example directory](example/auth-webhook) for a reference implementation that you can
customize to suit your needs.

You can also use just the authorization hook without also using the authentication hook.
Use of the authentication hook requires Athenz to be able to sign tokens for users.
