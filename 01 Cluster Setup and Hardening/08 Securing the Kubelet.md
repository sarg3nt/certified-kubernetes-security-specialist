# Securing the `kubelet`

The `kubelet` is like the captain on the ship.  He does all the work and reports back to the master

## `kubelet` Settings

`kubeadm` does not install the `kubelet` service but it can help with configuring    
In versions of Kubernetes older than 1.10 all of the `kubelet` config was done in the `kubelet` start command but as of 1.10 many of those options were moved to the `/var/lib/kubelet/config.yaml` file and `kubeadm` helps configure that file when you run the `kubeadm join` command

Note: Although configuration can be set in either the kubelet service config or in the `/var/lib/kubelet/config.yaml` file it is highly recommended that the `/var/lib/kubelet/config.yaml` file is used.

To know what options the `kubelet` was started with we can inspect the kubelet process on the node
```sh  
ps -aux | grep kubelet
```
In the results we see the `--config=/var/lib/kubelet/config.yaml` is telling us where most of the config is located  

## Disabling Anonymous Access
The `kubelet` serves its API on two ports:  

| Port    | Description |
| ------- | ----------- |
| 10250   | Serves API that allows full access |
| 10255   | Serves API that allows unauthenticated read-only access |

By default the `kubelet` allows anyone to access either API endpoint without authentication which is very dangerous  

To disable anonymous access set  
```sh
# /etc/systemd/system/kubelet.service
--anonymous-auth=false
```  
in the `kubelet` service configuration file or the external `/var/lib/kubelet/config.yaml`  
```yaml
authentication:
  anonymous:
    enabled: false
```

## `kubelet` Authentication

There are two Authentication mechanisms the kubelet supports, Certificates and Bearer Tokens  

The recommended method is to use Certificate based authentication by setting the
```sh
# /etc/systemd/system/kubelet.service
--client-ca-file=/path/to/ca.crt
```
 in the kubelet service config or the external `/var/lib/kubelet/config.yaml`
```yaml
authentication:
  x509:
    clientCAFile: /path/to/ca.crt
```

The `kube-apiserver` must also have the kubelet client certificates configured  

Note: We often think of the `kube-apiserver` as only a server supporting clients, but in this instance it is the client calling the `kubelet`  
```yaml
# Note: These are the same settings weather they are in the yaml file for a kubeadm based build or in the service config file at /etc/systemd/system/kube-apiserver.service for a service based build
- --kubelet-client-certificate=/path/to/kubelet-cert.pem
- --kubelet-client-key=/path/to/kubelet-key.pem
```

## Authorization

### `kubelet`

Once the user gains access to the system, what can they access?  
The default authorization mode is `AlwaysAllow`, to prevent this we set the authorization mode to webhook  
```sh
# /etc/systemd/system/kubelet.service
--authorization-mode=Webhook
```
```yaml
# kubelet-config.yaml
authorization:
  mode: Webhook
```
In this mode the kubelet sends a request to the `kube-apiserver` to see if it should approve or reject the request.

### Metrics Server

The metrics server usually runs on port 10255 and is `read allow` by all.  To disable this set the port to 0.  If the `kubelet` was configured by `kubeadm` then the port will be set to 0 in the `/var/lib/kubelet/config.yaml` file:  
```yaml
# kubelet-config.yaml
readOnlyPort: 0
```
or in the service config:  
```sh
# /etc/systemd/system/kubelet.service
--read-only-port:0
```