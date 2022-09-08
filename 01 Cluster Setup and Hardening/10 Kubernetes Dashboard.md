# Kubernetes Dashboard

By default the k8s dashboard is deployed with a service set to ClusterIP 

When set to ClusterIP we could use `k port-forward` to get access to the Dashboard from a local machine

It is not recommended to switch the dashboard service to `LoadBalancer` as that would make it public  

Switching the service to `NodePort` may be an option if we are confident our network is secure  

Another option is an Authentication Proxy such as the OAuth 2 Proxy which would perform the authentication and on success route traffic to the dashboard  

## Authentication Mechanisms for the Kubernetes Dashboard

The Dashboard supports two main authentication types:  

- Token
- kubeconfig

The Kubernetes Dashboard documentation page has a sample on creating a Service Account user and getting the token for Token based authentication.  Be careful as it creates a cluster admin

## References

- https://redlock.io/blog/cryptojacking-tesla
- https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/
- https://github.com/kubernetes/dashboard
- https://www.youtube.com/watch?v=od8TnIvuADg 
- https://blog.heptio.com/on-securing-the-kubernetes-dashboard-16b09b1b7aca
- https://github.com/kubernetes/dashboard/blob/master/docs/user/access-control/creating-sample-user.md