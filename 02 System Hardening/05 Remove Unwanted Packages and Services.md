# Remove Unwanted Packages and Services

Only install what is needed for the cluster.

Remove unneeded services.

```sh
systemctl list-units --type service
systemctl stop apache2
systemctl disable apache2

apt remove apache2
# OR
# Move or remove service file (below is for nginx and not apache2, but same thing basically)
# You can see where this file is by looking at output of `systemctl status <service>`
mv /lib/systemd/system/nginx.service ~/nginx.service

systemctl daemon-reload

# List currently installed packages
apt list --installed
```

## Reference links

Download the CIS benchmark PDF’s from the below link:

https://www.cisecurity.org/cis-benchmarks/

Go to the `Operating Systems` section and search for the `Distribution Independent Linux`. Expand it to see more options then download CIS Benchmark.