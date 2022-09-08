# Use Static Analysis of User Workloads

## `kubesec`

https://kubesec.io/

`kubesec` accepts one or more manifest files and scans them for issues  
Example Output:  
```json
[
  {
    "object": "Pod/security-context-demo.default",
    "valid": true,
    "message": "Failed with a score of -30 points",
    "score": -30,
    "scoring": {
      "critical": [
        {
          "selector": "containers[] .securityContext .capabilities .add == SYS_ADMIN",
          "reason": "CAP_SYS_ADMIN is the most privileged capability and should always be avoided"
        }
      ],
      "advise": [
        {
          "selector": "containers[] .securityContext .runAsNonRoot == true",
          "reason": "Force the running image to run as a non-root user to ensure least privilege"
        },
        {
          // ...
        }
      ]
    }
  }
]
```

`kubesec` can be installed several different ways.

- Docker container image at docker.io/kubesec/kubesec:v2
- Linux/MacOS/Win binary (get the latest release)
- Kubernetes Admission Controller
- Kubectl plugin

### Install `kubesec`
```sh
wget https://github.com/controlplaneio/kubesec/releases/download/v2.11.5/kubesec_linux_amd64.tar.gz
tar -xf kubesec_linux_amd64.tar.gz
sudo mv kubesec /usr/local/bin
```

### Usage

Command line usage  
```sh
kubesec scan k8s-deployment.yaml
# or
k get po grid-main-7bfb769655-2549s -o yaml | kubesec scan /dev/stdin | jq
```
Docker Usage
```sh
 docker run -i kubesec/kubesec:512c5e0 scan /dev/stdin < kubesec-test.yaml
 ```
 See docs at https://kubesec.io/ for more