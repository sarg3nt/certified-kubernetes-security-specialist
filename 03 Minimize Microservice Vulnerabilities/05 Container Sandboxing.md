# Container Sandboxing

The following techniques we discussed earlier are examples fo Sandboxing

- Seccomp
- AppArmor

The core problem is that all the containers all interact with the same OS and Kernel which the above do not solve

## gVisor

gVisor improves container isolation by inserting itself between the container and the kernel so syscalls go through gVisor

container --> syscall --> kernel  
becomes  
container --> syscall --> gVisor --> kernel  

gVisor has two components

- Sentry: acts as a kernel for containers 
- Gofer: A file proxy which impplements components needed for containers to talk to the file system
- gVisor has its own networking stack so the container does not need to interact with the host network

Each container has its own gVisor which isolates the containers from each other

Disadvantages of gVisor
- Not all apps work with gVisor
- Increases latency as there is more for the CPU to do

Whereas Docker uses `runC` as the base runtime, gVisor uses the `runsc` runtime to start containers

## Kata Containers

Kata inserts each container into it's own light weight VM  
This does add some latency and increases resource usage  
Many cloud providers do not support Kata as it requires nested virtualization which is usually very poor  
Works well for bare metal servers

Whereas Docker uses `runC` as the base runtime, kata uses the `kata` runtime to start containers.

## Using Runtimes in Kubernetes

Assuming we have gVisor installed on Kubernetes how do we make use of it in K8s  
First we need to create a new k8s object called a `RuntimeClass` that details what handler will be used  

`gvisor.yaml`
```yaml
apiVersion: node.k8s.io/v1beta1
kind: RuntimeClass
metadata: 
  name: gvisor
handler: runsc
```
Install it  
```sh
k create -f gvisor.yaml
```
Now we can create a pod using the new RuntimeClass  
`nginx.yaml`
```yaml
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: nginx
  name: nginx
spec:
  runtimeClassName: gvisor
  containers:
  - image: nginx
    name: nginx
```
Create the pod
```sh
k create -f nginx.yaml
```
Check to make sure nginx is not running on the node
```sh
pgrep -a nginx
```
Confirm that runsc is running
```sh
pgrep -a runsc
```
