# `kubectl` Proxy

## Accessing the `kube-api`

Normally if we want to access the `kube-apiserver` directly we need to specify our certificates in the `curl` command  
If we use the `kubectl proxy` command, it will start a proxy on port `8001` and use the connection information located in our `.kube/config` file to connect to the `kube-apiserver`.  
Once this is done, we can access the `kube-apiserver` over the proxy, without any further authentication.  
```bash
k proxy & # & starts it in the background
curl http://localhost:8001 -k # -k == set insecure
```
Note: The `kubectl` proxy accepts requests from local / loopback 127.0.0.1 only

## Accessing ClusterIP Services Via Proxy

We can access our services via the proxy using the api:

```sh
# Access the nginx proxy service called 'nginx' in the default namespace
curl http://localhost:8001/api/v1/namespaces/default/services/nginx/proxy/
```

## Accessing ClusterIP Services Via `port-forward`

We can also use `kubectl port-forward` to directly access a service.  
```sh
# port forward our local port 28080 to the cluster service port 80
k port-forward service/nginx 28080:80
# Then call it
curl http://localhost:28080/
```
