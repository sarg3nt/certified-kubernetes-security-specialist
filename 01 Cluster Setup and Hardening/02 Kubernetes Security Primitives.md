# Kubernetes Security Primitives

This is a brief overview of the components, we will go over each of these in greater detail in upcoming lectures.

First line of defense is securing access to the `api-server`.

## Authentication

- Files - Username and Password
- Files - Username and Tokens
- Certificates
- External Authentication providers - LDAP
- Service Accounts (for machine access)

## Authorization

What can they do?

- RBAC Authorization
- AVAC Authorization
- Node Authentication
- Webhook Mode

## TLS Certificates

Secure the communication between different core components.

## Network Policy

Control what pods can talk to what.  
By default all pods can talk to all other pods in the cluster.