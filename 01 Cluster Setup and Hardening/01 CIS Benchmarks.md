# CIS Benchmarks

Center for Information Security.

Security benchmarks.

- Physical USB ports disable
- root disabled, users must log in and `sudo`
- Configure firewall / iptables to only open ports needed
- All services not absolutely required are disabled.
- Right permissions are set for files
- Unused file systems are disabled
- Configure auditing and logging to make sure all changes are logged for auditing.
- Upgrade, patch and configure to avoid new attacks.

The CIS benchmarking tool is one of the most used tools to determine how secure your server is.

## CIS Benchmarks for Ubuntu (lab)

CIS-Cat Lite or Pro

Here we ran the CIS Benchmark for Ubuntu
```bash
# Run in interactive mode
sh ./Assessor-CLI.sh -i

# Run in interactive mode, store in /var/www/html/ as index.html
sh ./Assessor-CLI.sh -i -rd /var/www/html/ -nts -rp index
```

## CIS Benchmarks for Kubernetes

CIS-CAT Lite does not support Kubernetes, but pro does in version 4.

## Reference links

Download the CIS benchmark PDF’s from the below link:

https://www.cisecurity.org/cis-benchmarks/#kubernetes

Go to the `Server Software` section and click on the `Virtualization`. 

There you will see multiple items that fall into the virtualization category such as VMware, docker and kubernetes. Now, move on to the Kubernetes and expand it to see more options then download CIS Kubernetes Benchmark version 1.6.0.

Download the CIS CAT tool’ from the below link: 

https://www.cisecurity.org/cybersecurity-tools/cis-cat-pro/cis-benchmarks-supported-by-cis-cat-pro/

## `kube-bench`

`kube-bench` is an open source tool by Aqua Security that covers all of the CIS benchmark items for Kubernetes.

```bash
wget https://github.com/aquasecurity/kube-bench/releases/download/v0.4.0/kube-bench_0.4.0_linux_amd64.tar.gz
tar -xf kube-bench_0.4.0_linux_amd64.tar.gz 
./kube-bench --config-dir `pwd`/cfg --config `pwd`/cfg/config.yaml 
```