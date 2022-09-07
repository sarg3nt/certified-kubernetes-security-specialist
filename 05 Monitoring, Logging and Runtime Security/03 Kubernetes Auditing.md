# Kubernetes Auditing

## Use Audit Logs to Monitor Access

The `kube-apiserver` handles auditing out of the box but it is not enabled by default 

`kube-apiserver` requests go through the following stages  
1. RequestReceived: After receive before any work
1. ResponseStarted: Applicable to long running tasks like `watch`
1. ResponseComplete: When all requested data is sent
1. Panic: If there was an error

Each of these stages generate events that can be recorded by the `kube-apiserver` but it does not do this by default  
If we record all the events created by the cluster there would be hundreds of thousands of events  
Typically we want to narrow down what we audit to critical components, specific namespaces, etc.  

We can manage what is recorded with audit policies
audit-policy.yaml
```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: ["RequestReceived"] # Optional
rules: 
  - namespace: ["prod-namespace"] # Optional
    verbs: ["delete"] # Optional
    resources: 
    - groups: " "
      resources: ["pods"]
      resourceName: ["webapp-pod"] # Optional
    level: RequestResponse # None, Metadata, Request, RequestResponse
  - level: Metadata
    resources:
    - groups: " "
      resources: ["secrets"]
```

## Enable Auditing

Two types of backends are supported  
- Log backend: Stores files locally on disk
- Webhook backend:  Makes use of a remote backend such as a Falco service

To enable auditing we have to pass the following commands into the `kube-apiserver`  
```yaml
- --audit-log-path=/var/log/k8s-audit.log # location of the audit log
- --audit-policy-file=/etc/kubernetes/audit-policy.yaml # Our policy file we created above
- --audit-log-maxage=10 # in days
- --audit-log-maxbackup=5 # number of files to retain on the host
- --audit-log-maxsize=100 # Max size of file in megabytes before being rotated
```
**NOTE:** Don't forget that when pointing to file locations as we do above that you must mount those paths as volumes