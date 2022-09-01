# Disable Open Ports

```sh
# Check if port is open and listening
netstat -an | grep -w LISTEN

# On Ubuntu check what ports are used by what services
cat /etc/services | grep -w 53
# domain 53/tcp       # Domain Name Server
# domain 53/udp

# OR
netstat -natp | grep 9090

# Look at documentation for what software needs what ports open
```

## Reference links

Download the CIS benchmark PDF’s from the below link:

https://www.cisecurity.org/cis-benchmarks/

Go to the `Operating Systems` section and search for the `Distribution Independent Linux`. Expand it to see more options then download CIS Benchmark.

Below are some references:

https://access.redhat.com/security/cve/cve-2019-3874

https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/#check-required-ports