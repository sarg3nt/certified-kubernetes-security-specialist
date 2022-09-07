# 02 Immutable Infrastructure

## Mutable Infrastructure

An example of Mutable Infrastructure would be a web server running NGINX 1.17.  
When a new version of NGINX comes out, admins upgrade the running version using one of several methods, from built in package managers to IAC such as Ansible.  
This type of upgrade is called an "In Place" upgrade.  
The servers must have all the dependencies needed for the upgrade or it will fail.  
There are failure scenarios where some servers have all of the dependencies and some do not so those that do not fail during upgrade.
This can lead to a situation where some servers are on different versions than others in a cluster.  This is known as configuration drift  

## Immutable Infrastructure

Instead of updating the software on a server we can spin up a new server with the new version on it.  This is a property of immutable infrastructure.  

The "server" is not updatable.

Containers are considered Immutable but can actually be changed.  

## Ensure Immutability of Containers at Runtime

### `readOnlyRootFilesystem`

Set the file system of the container to read only to prevent changes during runtime  
```yaml
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: nginx
  name: nginx
spec:
  containers:
  - image: nginx
    name: nginx
    securityContext:
      readOnlyRootFilesystem: true
```
This will cause NGINX to fail as it needs to write to certain files.  
The solution is to mount `emptyDir` volumes to the paths that need written to  
```yaml
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: nginx
  name: nginx
spec:
  containers:
  - image: nginx
    name: nginx
    securityContext:
      readOnlyRootFilesystem: true
    volumeMounts:
    - name: cache-volume
      mountPath: /var/cache/nginx
    - name: runtime-volume
      mountPath: /var/run
   volumes:
   - name: cache-volume
     emptyDir: {}
   - name: runtime-volume
     emptyDir: {}     
```

### `privileged: true` Breaks Immutability

If `privileged: true` is set on a container with `readOnlyRootFilesystem: true` most of the file system is still immutable, however the `/proc/` file system is writable.  
An attacher could `echo '75' > /proc/sys/vm/swappiness` and modify swappiness for both the container AND the host  

