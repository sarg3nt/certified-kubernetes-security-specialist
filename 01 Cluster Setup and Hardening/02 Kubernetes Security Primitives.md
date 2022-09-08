# Kubernetes Security Primitives

This is a brief overview of the components, we will go over each of these in greater detail in upcoming lectures

First line of defense is securing access to the `kube-apiserver`

## Authentication

Mechanisms for securing access to the `kube-apiserver`  
See [Authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/) in the Kubernetes docs for more information

- Files - Username and Password:  Do not use
- Files - Username and Tokens: Do not use
- Certificates: Preferred if external authentication is not an option
- Service Accounts: For machine / software access
- External Authentication providers: Preferred if available

## Authorization

What can they do?

- [RBAC Authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/): Role based access control.  More common in K8s
- [ABAC Authorization](https://kubernetes.io/docs/reference/access-authn-authz/abac/): Attribute based access control
- [Node Authorization](https://kubernetes.io/docs/reference/access-authn-authz/node/): Node authorization is a special-purpose authorization mode that specifically authorizes API requests made by kubelets
- [Webhook Mode](https://kubernetes.io/docs/reference/access-authn-authz/webhook/): When specified, mode Webhook causes Kubernetes to query an outside REST service when determining user privileges.

## TLS Certificates

Secure the communication between different core components

## Network Policy

Control what pods can talk to what  
By default all pods can talk to all other pods in the cluster, this is not good for security