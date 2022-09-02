# Security Contexts

We can choose to configure k8s security levels at either the pod or container level  
Container level security overrides pod level

Pod level
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: web-pod
spec:
  securityContext:
    runAsUser: 1000
  containers:
  - name: ubuntu
    image: ubuntu
    command: ["sleep","3600"]
```
Container level, just move the whole thing inside of the containers section
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: web-pod
spec:
  containers:
  - name: ubuntu
    image: ubuntu
    command: ["sleep","3600"]
    securityContext:
      runAsUser: 1000
      # NOTE: capabilities are only supported at the container level
      capabilities:
        add: ["MAC_ADMIN"]
```