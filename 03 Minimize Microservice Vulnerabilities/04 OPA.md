# OPA

Open Policy Agent

OPA takes care of Authorization, not Authentication

The exam won't have us write policy files but we should know how to work with them and what they do.

Install OPA
```bash
curl -L -o opa https://github.com/open-policy-agent/opa/releases/download/v0.11.0/opa_linux_amd64
chmod 755 ./opa
./opa run -s
```
Output
```text
{"addrs":[":8181"],"insecure_addr":"","level":"info","msg":"First line of log 
stream.","time":"2021-03-18T20:25:38+08:00"}
```
Note: By default authentication and authorization are disabled.

An example OPA rule in the Rego policy language
example.rego
```sh
package httpapi.authz

# HTTP API request
import input

default allow = false

allow {
  input.path == "home"
  input.user == "john"
}
```
Install the rule.  Default port is 8181
```sh
curl -X PUT --data-binary @example.rego http://localhost:8181/v1/policies/example1
curl http://localhost:8181/v1/policies
```

Simple example of using the above rule in Python
```python
@app.route('/home')
def hello_world():

  user = request.args.get("user")
  # Create a dict to send to OPA
  input_dict = {
    "input": {
    "user": user,
    "path": "home",  
    }
  }

  # This is our OPA endpoint
  rsp = requests.post("http://127.0.0.1:8181/..authz", json=input_dict)
   
  if not rsp.json()["result"]["allow"]:
    return 'Unauthorized!', 401
  
  return 'Welcome Home!', 200
```

## Videos to Watch to Learn More about OPA

How Netflix Is Solving Authorization Across Their Cloud [I] - Manish Mehta & Torin Sandall, Netflix
https://www.youtube.com/watch?v=R6tUNpRpdnY

OPA Deep Dive
https://www.youtube.com/watch?v=4mBJSIhs2xQ

# OPA in Kubernetes

With OPA in Kubernetes we can point our Validating and Mutating Webhooks at OPA instead of creating our own server and hosting the API  

An example of a Validating Webhook Configuration pointing to the k8s service for an OPA install
```yaml
apiVersion: admissionregistration.k8s.io/v1beta1 
kind: ValidatingWebhookConfiguration
metadata:
  name: opa-validating-webhook
webhooks:
  - name: validating-webhook.openpolicyagent.org
    rules:
    - operations: ["CREATE", "UPDATE"]
      apiGroups: ["*"]
      apiVersions: ["*"]
      resources: ["*"]

    clientConfig:
      caBundle: $(cat ca.crt | base64 | tr -d '\n')
      service:
        namespace: opa
        name: opa
```
Example data coming in for a pod creation
```json
{
  "kind": "AdmissionReview",
  "request": {
    "kind": {
      "kind": "Pod",
      "version": "v1"
    },
    "object": {
      "metadata": {
        "name": "myapp"
      },
      "spec": {
        "containers": [
          {
          "image": "nginx",
          "name": "nginx-frontend"
          },
          {
          "image": "mysql",
          "name": "mysql-backend"
          }
        ]
      }
    }
  }
}
```

Validating against this policy
kubernetes.rego
```js
package kubernetes.admission

deny[msg] {
  input.request.kind.kind == "Pod" 
  image := input.request.object.spec.containers[_].image
  startswith(image, "hooli.com/") 
  msg := sprintf("image '%v' from untrusted registry", [image])
}
```
https://www.openpolicyagent.org/docs/latest/kubernetes-primer/

When installed in k8s we insert the .rego via a `ConfigMap`
```yaml
kind: ConfigMap
apiVersion: v1
metadata:
  name: policy-unique-podname
  namespace: opa
  labels:
    openpolicyagent.org/policy: rego
data:
  main: |
    package kubernetes.admission

    import data.kubernetes.pods

    deny[msg]{
      input.request.kind.kind == "Pod"
      input_pod_name := input.request.object.metadata.name
      other_pod_names := pods[other_ns][other_name].metadata.name
      input_pod_name == other_pod_names
      msg := sprintf("Podname '%v' already exists")
    }
```

When we install OPA into Kubernetes a sidecar called `kube-mgmt` is created in the OPA pod.  This side car loads Kubernetes objects so OPA knows what resources are deployed.  It also loads ConfigMap policies into OPA that have labels of `openpolicyagent.org/policy: rego`

## References

- https://kubernetes.io/blog/2019/08/06/opa-gatekeeper-policy-and-governance-for-kubernetes/
- https://www.openpolicyagent.org/docs/v0.12.2/kubernetes-admission-control/
- https://www.openpolicyagent.org/docs/latest/kubernetes-tutorial/
- https://www.openpolicyagent.org/docs/v0.11.0/guides-kubernetes-admission-control/
- https://www.youtube.com/watch?v=QU9BGPf0hBw