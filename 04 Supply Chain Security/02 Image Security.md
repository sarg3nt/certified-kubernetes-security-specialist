# Image Security

An image reference that does not state the server, like `nginx` 
```yaml
image: nginx
```
really looks like this  
```yaml
image: docker.io/library/nginx
     # registry, user/, image/
     #          account  repository
```

Use a private registry that is private and accessed from a set of credentials  

We need to create a `docker-registry` secret that has the server url, user, password and email needed for Docker to pull the image
```sh
k create secret docker-registry regcred \
  --docker-server=private-registry.io \
  --docker-username=registry-user \
  --docker-password=registry-password \
  --docker-email=registry-user@org.com
```
We can then use that secret in the pod spec
```yaml
apiVersion: v1
kind: Pod
metadata: 
  name: nginx-pod
spec: 
  containers:
  - name: nginx
    image: private-registry.io/apps/internal-app
imagePullSecrets:
- name: regcred
```
The kubelet on the node uses the secret to pull the images