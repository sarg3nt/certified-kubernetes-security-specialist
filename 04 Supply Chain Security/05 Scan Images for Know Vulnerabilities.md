# Scan Images for Know Vulnerabilities

## What is a CVE

Common Vulnerabilities and Exposures (CVE)  
A central database that anyone can submit vulnerabilities and exposures to  
Each CVE gets a unique identifier

What kind of bugs get CVEs?  Usually one of the following: 
- Anything that lets an attacker bypass security and do something they should not be able to
- Anything that allows an attacker to degrade performance / interrupt service, etc. 

CVSS v3.0 ratings have the following levels.
- None 0.0
- Low 0.1 - 3.9
- Medium 4.0 - 6.9
- High 7.0 - 8.9
- Critical 9.0 - 10.0

## CVE Scanner

Looks at services on our system and displays a list of vulnerabilities  

Once we've identified a vulnerability we can mitigate it in one of the following ways

- Upgrade the component if a new version fixes it
- Uninstall the component if we do not need it
- Apply some mitigating or compensating control if they exist

## Vulnerability Scanner Trivy

By Aqua Security

```sh
# Get help
trivy 
trivy image --help

# Basic usage
trivy image nginx:1.18.0

# Filter out only HIGH and CRITICAL
trivy image --severity CRITICAL,HIGH nginx:1.18.0

# Ignore unfixed vulns
trivy image --ignore-unfixed nginx:1.18.0

# Us a tar image as input
docker save nginx:1.18.0 > nginx.tar
trivy image --input archive.tar

# Output of json to a directory
trivy image --format json --output /location/file nginx
```

## Best Practices

- Continuously rescan images
- Kubernetes Admission Controllers to scan images OR
- Use a private repository with pre-scanned images ready to go
- Integrate scanning into CI/CD pipeline

