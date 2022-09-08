# Validating and Mutating Admission Controllers

- Validating Admission Controllers validate a spec and block it if it does not meet the validation  
Example: The `NamespaceExists` admission controller will bock the creation of a resource if the requested namespace does not exist
- Mutating Admission Controllers will validate a spec and add or change it if necessary  
Example: The `DefaultStorageClass` admission controller will ADD a storage class to a PVC spec if it does not have one

Mutating ACs are generally ran before Validating ACs

## Creating our Own ACs

To facilitate the creation of custom ACs there are two built in ACs called `MutatingAdmissionsWebhook` and `ValidatingAdmissionWebhook`

Webhook processing takes place after all the other built in ACs  

### Develop and Deploy a Webhook Service  

We need a service the webhook can call to evaluate the manifest file and reply with an allow or reject  
See the example [admission webhook server](https://github.com/kubernetes/kubernetes/blob/release-1.21/test/images/agnhost/webhook/main.go) written in Go   
More details in the [Dynamic Admission Control](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#write-an-admission-webhook-server) k8s documentation  
This can then be deployed as a deployment on the k8s cluster with a service or can be an external URL
### Create a Validating Webhook Configuration Object

```yaml
apiVersion:  admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
name: "pod-policy.example.com"
webhooks:
- name: pod-policy.example.com
# The service we built to handle the webhook and do the processing
clientConfig:  
  url: "https://fqdn"
  #OR
  service:
  namespace: "webhook-namespace"
  name: "webhook-service"
  # We need a cert bundle that the called service is configured with
  caBundle: "Ci0t......tls0K"
# When to call the service
rules:
- apiGroups: [""]
  apiVersion: ["v1"]
  operations: ["CREATE"]
  resources: ["pods"]
  scope: "Namespaced"
```