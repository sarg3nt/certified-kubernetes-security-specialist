# SSH Hardening

```sh
# Generate a new public private key pair into the ~/.ssh directory
ssh-keygen # default type is '-t rsa'

# Copy public key to remote server
ssh-copy-id mark@node01
# this will copy the public key to the ~/.ssh/authorized_keys file as a new line
```

## Disable `ssh` for `root` and Password Based Authentication

```sh
# edit
vi /etc/ssh/sshd_config
# and set PermitRootLogin to no
PermitRootLogin no
 
# Disable password based authentication
# Make sure there are public keys that can access the node first
PasswordAuthentication no

# exit and save then reload sshd
systemctl reload sshd
```
Refer to section 5.2 of the CIS Benchmarks for distribution independent Linux

## References

Download the CIS benchmark PDF’s from the below link:  
https://www.cisecurity.org/cis-benchmarks/

Go to the `Operating Systems` section and search for the `Distribution Independent Linux`  
Expand it to see more options then download CIS Benchmark