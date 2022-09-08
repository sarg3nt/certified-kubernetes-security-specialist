# Admission Controllers

Admission controllers live between the authentication/authorization step and the kub-api performing the work.

There are a number of Admission Controllers that come with recent Kubernetes versions.
- AlwaysPullImages
- DefaultStorageClass
- EventRateLimit (for limiting the api rate)
- NamespaceExists
- Many More

We can see which admission controllers are active by interrogating the `kube-apiserver`
```sh
kube-apiserver -h | grep enable-admission-plugins

# If this is a kubeadm created cluster, we must run this in the pod
kubectl exec kube-apiserver-controlplane -n kube-system -- kube-apiserver -h | grep enable-admission-plugins
```
Output
```text
--enable-admission-plugins strings       admission plugins that should be enabled in addition to default enabled ones (NamespaceLifecycle, LimitRanger, ServiceAccount, TaintNodesByCondition, Priority, DefaultTolerationSeconds, DefaultStorageClass, StorageObjectInUseProtection, PersistentVolumeClaimResize, RuntimeClass, CertificateApproval, CertificateSigning, CertificateSubjectRestriction, DefaultIngressClass, MutatingAdmissionWebhook, ValidatingAdmissionWebhook, ResourceQuota) . . . 
```
Or use `ps`
```sh
ps -ef | grep kube-apiserver | grep admission-plugins
```
Output
```text
. . . --enable-admission-plugins=NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,DefaultTolerationSeconds,MutatingAdmissionWebhook,ValidatingAdmissionWebhook,ResourceQuota,NodeRestriction,Priority,TaintNodesByCondition,PersistentVolumeClaimResize,PodSecurityPolicy . . .
```

To add an admission controller update the `--enable-admission-plugins` paramater where the `kube-apiserver` is configured.  We can also disable using the `--disable-admission-plugins`
```sh
...
--v=2
--enable-admission-plugins=NodeRestriction,NamespaceAutoProvision
--disable-admission-plugins=DefaultStorageClass
...
```

Note that the `NamespaceExists` and `NamespaceAutoProvision` admission controllers are deprecated and now replaced by `NamespaceLifecycle` admission controller

The `NamespaceLifecycle` admission controller will make sure that requests to a non-existent namespace is rejected and that the default namespaces such as `default`, `kube-system` and `kube-public` cannot be deleted