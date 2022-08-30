# Verify Platform Binaries Before Deploying

When downloading kubernetes manually we must compare our downloaded file's hash to that listed on the Kubernetes Release Notes page.

```sh
shasum -a 512 kubernetes.tar.gz # mac
sha512sum kubernetes.tar.gz # linux
```

## Reference links

Release Notes:  

https://github.com/kubernetes/kubernetes/tree/master/CHANGELOG