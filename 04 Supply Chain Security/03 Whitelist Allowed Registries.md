# Whitelist Allowed Registries

1. Use OPA as shown in previous sections
1. Use Image Policy Webhook

## Image Policy Webhook

We need an Admission Webhook Server

```yaml
# /etc/kubernetes/admission-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: ImagePolicyWebhook
  configuration:
    imagePolicy:
      kubeConfigFile: <path-to-config-file> # Config to talk to the Admission Webhook Server
      allowTTL: 50
      denyTTL: 50
      retryBackoff: 500
      defaultAllow: true # If admission webhook server does not exist or does not respond in time or does not explicitly deny the request
```
Kube Config File for above
```yaml
cluster:
- name: name-of-remote-imagepolicy-service
  cluster:
    certificate-authority: /path/to/ca.pem
    server: https://images.example.com/policy

users:
- name: name-of-api-server
  user:
    client-certificate: /pth/to/cert.pem
    client-key: /path/to/key.pem
```
Add it to the `kube-apiserver` configuration  
Make sure you do not accidentally create two config entries for --enable-admission-plugins  
```yaml
- --enable-admission-plugins=ImagePolicyWebhook
- --admission-control-config-file=/etc/kubernetes/admission-config.yaml
```
**Reminder:** Any config in a pod that is pointing to a file needs to have a volume mounted to the host OS if that is where the config is located