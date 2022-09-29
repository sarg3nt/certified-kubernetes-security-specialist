# Authentication

Types of users include:
- Admins
- Developers
- Application end users
- Bots / Machines

Here we will talk about users accessing the cluster, not the end user applications    

We have two types of users, humans and bots  

Kubernetes does not manage "Human" end users, it relies on other authentication mechanisms such as LDAP  
Kubernetes can manage bot accounts using "Service Accounts"  

The `kube-apiserver` manages all access to the Kubernetes cluster weather it be via `kubectl` or the API directly.

The `kube-apiserver` supports the following authentication mechanisms

- Static Password File
- Static Token File
- Certificates
- Identity Service

## Basic Auth Mechanisms - Files

### Warning

These are not a recommended method as tokens and passwords are stored in clear text files

### Static Password File

A file like `user-details.csv` is generated.

```csv
# user-details.csv
password1,username1,userid2
password2,username2,userid2
...
```
We then pass this file as an option to the `kube-apiserver`  
`--basic-auth-file=user-details.csv`

To then authenticate the API server with basic credentials, specify the user in a `curl` command like this.

`curl -v -k https://master-node-ip:6443/api/v1/pods -u "user1:password1"`

The above `csv` file can optionally have a group column to assign users to groups

### Static Token File

Instead of passwords, you can specify a token

```csv
# user-token-details.csv
fk4kslv9ckdlekjkcvx00v9dlsdkfls8vosk,username1,userid1
zvk4lc9lfnj4ffldc9bjklemcleedl3j50jf,username2,userid2
...
```
Then in the `kube-apiserver` config add:  
```yaml
- --token-auth-file=user-token-details.csv
```
Reminder: Any file access done in a pod needs to be backed by a volume to the source on the node.

When authenticating, specify the token as an Authorization Bearer Token:  
```sh
curl -v -k https://master-node-ip:6443/api/v1/pods --header "Authorization: Bearer fk4kslv9ckdlekjkcvx00v9dlsdkfls8vosk"
```

# Article on Setting up Basic Authentication

**This is a direct copy from the training and is deprecated as of 1.19, here for historic purposes only**

Setup basic authentication on Kubernetes (Deprecated in 1.19)  
Note: This is not recommended in a production environment. 
This is only for learning purposes. 
Also note that this approach is deprecated in Kubernetes version 1.19 and is no longer available in later releases

Follow the below instructions to configure basic authentication in a kubeadm setup.

Create a file with user details locally at /tmp/users/user-details.csv

## User File Contents
```csv
password123,user1,u0001
password123,user2,u0002
password123,user3,u0003
password123,user4,u0004
password123,user5,u0005
```

Edit the kube-apiserver static pod configured by kubeadm to pass in the user details.  
The file is located at `/etc/kubernetes/manifests/kube-apiserver.yaml`

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
  - command:
    - kube-apiserver
      <content-hidden>
    image: k8s.gcr.io/kube-apiserver-amd64:v1.11.3
    name: kube-apiserver
    volumeMounts:
    - mountPath: /tmp/users
      name: usr-details
      readOnly: true
  volumes:
  - hostPath:
      path: /tmp/users
      type: DirectoryOrCreate
    name: usr-details
```

Modify the `kube-apiserver` startup options to include the basic-auth file

```yaml
apiVersion: v1
kind: Pod
metadata:
  creationTimestamp: null
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
  - command:
    - kube-apiserver
    - --authorization-mode=Node,RBAC
      <content-hidden>
    - --basic-auth-file=/tmp/users/user-details.csv
```

Create the necessary roles and role bindings for these users:

```yaml
---
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  namespace: default
  name: pod-reader
rules:
- apiGroups: [""] # "" indicates the core API group
  resources: ["pods"]
  verbs: ["get", "watch", "list"]

---
# This role binding allows "jane" to read pods in the "default" namespace.
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: read-pods
  namespace: default
subjects:
- kind: User
  name: user1 # Name is case sensitive
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role #this must be Role or ClusterRole
  name: pod-reader # this must match the name of the Role or ClusterRole you wish to bind to
  apiGroup: rbac.authorization.k8s.io
```

Once created, you may authenticate into the kube-api server using the users credentials

`curl -v -k https://localhost:6443/api/v1/pods -u "user1:password123"`