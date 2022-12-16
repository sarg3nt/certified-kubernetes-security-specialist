# Cliff Notes
[[11 AppArmor]]

This page will attempt to distill the training down to a single, consumable file to ease memorization

## Generating a Private and Public Key Pair With OpenSSL
```sh
# Generate the private key
openssl genrsa -out my-bank.key 1024
# Use the private key to generate a public key
openssl rsa -in my-bank.key -pubout > mybank.pem
```
Create a certificate request using openssl
```sh
openssl req -new -key my-bank.key -out my-bank.csr -subj "/C=US/ST=CA/O=MyOrg, Ince/CN=mydomain.com"
```
## CA Key and Cert
```sh
# Generate certificate authority key if you don't have one
openssl genrsa -out ca.key 2048
# output is ca.key

# Create certificate signing request
openssl req -new -key ca.key -subj \
  "/CN=KUBERNETES-CA" -out ca.csr
# output is ca.csr

# Sign Certificate using the key we generated in step 1 which is our Certificate Authority key.
openssl x509 -req -in ca.csr -signkey ca.key -out ca.crt
# output is ca.crt
```
## Admin User Key and CSR
```sh
# Generate the key
openssl genrsa -out admin.key 2048
# output is admin.key

# Create certificate signing request
openssl req -new -key admin.key -subj \
  "/CN=kube-admin/O=system:masters" -out admin.csr
# output is admin.csr
# MUST mention system:masters group in test

# Sign Certificate.  This command is slightly different as it uses the ca.crt AND the ca.key
openssl x509 -req -in admin.csr –CA ca.crt -CAkey ca.key -out admin.crt
# output is admin.crt
# Note: you may need to pass -CAcreateserial the first time to tell it to create ca.srl file for serial number generation for that cert
```
## Verify Platform Binaries Before Deploying
```sh
sha512sum kubernetes.tar.gz
```
## ssh
```sh
ssh-keygen # default type is '-t rsa'
ssh-copy-id mark@node01
```
### Disable `ssh` for `root` and Password Based Authentication
```sh
vi /etc/ssh/sshd_config
# and set PermitRootLogin to no
PermitRootLogin no
# Disable password based authentication
# Make sure there are public keys that can access the node first
PasswordAuthentication no
# exit and save then reload sshd
systemctl reload sshd
```
## Blacklist Linux Kernel Modules
```sh
# Add a module manually
modprobe pcspkr
# list all modules loaded
lsmod
# Blacklist modules: The sctp module is not commonly used
cat /etc/modprobe.d/blacklist.conf
blacklist sctp
# Then reboot node
# Note: Unprivileged Containers can cause modules to load into the kernel by creating a network socket
```
## Disable Open Ports
```sh
# Check if port is open and listening
# -a is all, -n is numeric
netstat -an | grep -w LISTEN
# On Ubuntu check what ports are used by what services
cat /etc/services | grep -w 53
# domain 53/tcp       # Domain Name Server
# domain 53/udp
```
##  Using UFW
```sh
# See what ports are open
# -a is all, -n is numeric
netstat -an | grep -w LISTEN

# we want to allow 22 and 80 from two IPs
# First allow all default outgoing connections and block incoming.  These rules will not take immediate effect because ufw is currently disabled.
ufw default allow outgoing
ufw default deny incoming

# Add first IP to allow
# `to any` refers to the interfaces on the current machine
ufw allow from 172.16.238.5 to any port 22 proto tcp
ufw allow from 172.16.238.5 to any port 80 proto tcp

# Now the other machine
ufw allow from 172.16.100.0/28 to any port 80 proto tcp

# There appears to be no `ufw allow --help`
ufw allow 80

# Now block the port 8080 we don't want used
# This is not really needed as we have already blocked all incoming but is OK to create
ufw deny 8080 proto tcp

# deny a range of ports
ufw deny 1000:15000 proto tcp

# Reset rules to default
ufw reset

# Enable the firewall
ufw enable

ufw status

# To delete a rule
ufw delete deny 8080

# We can also use the row number from 
ufw status numbered
# If we want to the delete the fifth rule
ufw delete 5
```
## Linux `syscalls` and `seccomp`
### Determine what `syscalls` an application uses with `strace`
```sh
strace touch /tmp/error.log
# execve("/usr/bin/touch", ["touch", "/tmp/error.log"], 0x7ffdb5aef278 /* 40 vars */) = 0

# to trace a running process we need the pid
pidof etcd
# Now use that pid to attach to the process with strace
strace -p 3596

# -c or --summary-only will provide a summary
strace -c touch /tmp/error.log
```
Results
```text
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
  0.00    0.000000           0         3           read
  0.00    0.000000           0        22           close
```
### Aquasec Tracee
Used to trace system calls on containers
```sh
# To trace "command" of "ls"
docker run --name tracee --rm --privileged --pid=host \
  -v /lib/modules/:/lib/modules/:ro \
  -v /usr/src:/usr/src:ro \
  -v /tmp/tracee:/tmp/tracee \
  aquasec/tracee:0.4.0 --trace comm=ls

# To trace all new pids on the host
...
  aquasec/tracee:0.4.0 --trace pid=new

# Trace all new containers
...
  aquasec/tracee:0.4.0 --trace container=new
```
### Restrict `syscalls` with `seccomp`
Check if seccomp is installed
```sh
grep -i seccomp /boot/config-$(uname -r)
```
Output
```text
CONFIG_SECCOMP=y
```
Run the whalesay conatiner
```sh
docker run docker/whalesay cowsay hello!

# Now run the same image but exec in
docker run -it --rm docker/whalesay /bin/sh

# Try to set date
date -s '19 APR 2012 22:00:00'
# fails

# Check pid of shell
ps -ef
```
results
```text
UID        PID  PPID  C STIME TTY      TIME CMD
root         1     0  0 18:38 pts/0    00:00:00 /bin/sh
root         8     1  0 18:38 pts/0    00:00:00 ps -ef
```
Using the pid of the shell, check for seccomp status
```sh
grep Seccomp /proc/1/status
```
Results
```text
Seccomp:        2
Seccomp_filters:
```
seccomp has three modes it can be in 
| Mode | Meaning |
| ---- | ---------- |
| Mode 0 | DISABLED |
| Mode 1 | STRICT |
| Mode 2 | FILTERED |

Docker has a built in seccomp filter it applies that restricts about 60 of the calls including the ptrace syscall

### `seccomp` in Kubernetes

```sh
# First let's inspect what is configured using amicontained container
docker run r.j3ss.co/amicontained amicontained
# 61 syscalls blocked, this is the docker default
# Seccomp is filtering

# Ran this on the test cluster on 9/1/22
k run amicontained --image=r.j3ss.co/amicontained amicontained -- amicontainer
# seccomp is disabled because Kubernetes does not enable it by default
# 23 SysCalls blocked
```
Run the same pod but via a definition file with seccomp enabled
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: amicontained
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  nodeName: lpul-k8stestwrk09
  containers:
  - args:
    - amicontained
    image: r.j3ss.co/amicontained
    name: amicontained
    securityContext:
      allowPrivilegeEscalation: false
  dnsPolicy: ClusterFirst
  restartPolicy: Never
```
Result:
```text
Container Runtime: kube
Has Namespaces:
        pid: true
        user: false
AppArmor Profile: docker-default (enforce)
Capabilities:
        BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap
Seccomp: filtering
Blocked syscalls (63):
        MSGRCV SYSLOG SETPGID SETSID USELIB USTAT SYSFS VHANGUP PIVOT_ROOT _SYSCTL ACCT SETTIMEOFDAY MOUNT UMOUNT2 SWAPON SWAPOFF REBOOT SETHOSTNAME SETDOMAINNAME IOPL IOPERM CREATE_MODULE INIT_MODULE DELETE_MODULE GET_KERNEL_SYMS QUERY_MODULE QUOTACTL NFSSERVCTL GETPMSG PUTPMSG AFS_SYSCALL TUXCALL SECURITY LOOKUP_DCOOKIE CLOCK_SETTIME VSERVER MBIND SET_MEMPOLICY GET_MEMPOLICY KEXEC_LOAD ADD_KEY REQUEST_KEY KEYCTL MIGRATE_PAGES UNSHARE MOVE_PAGES PERF_EVENT_OPEN FANOTIFY_INIT NAME_TO_HANDLE_AT OPEN_BY_HANDLE_AT CLOCK_ADJTIME SETNS PROCESS_VM_READV PROCESS_VM_WRITEV KCMP FINIT_MODULE KEXEC_FILE_LOAD BPF USERFAULTFD MEMBARRIER PKEY_MPROTECT PKEY_ALLOC PKEY_FREE
Looking for Docker.sock
```
### Create a custom seccomp profile
```sh
# These must be created in the k8s default seccomp profile directory which is typically /var/lib/kubelet/seccomp
# Create a profiles directory
mkdir -p /var/lib/kubelet/seccomp/profiles

# Create an audit profile that will log syscalls
echo -e "{\n    \"defaultAction\": \"SCMP_ACT_LOG\"\n}" > /var/lib/kubelet/seccomp/profiles/audit.json
```
Create the pod on lpul-k8stestwrk09
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-audit
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      # This path must be relative to k8s default seccomp profile which is stored in /var/lib/kubelet/seccomp/
      localhostProfile: profiles/audit.json
  nodeName: lpul-k8stestwrk09
  containers:
  - command: ["bash", "-c", "echo 'I just made some syscalls' && sleep 100"]
    image: ubuntu
    name: ubuntu
    securityContext:
      allowPrivilegeEscalation: false
  restartPolicy: Never
```

View the logs on the node at /var/log/syslog
```sh
sudo grep syscall /var/log/syslog
```
Output
```text
Sep  1 10:39:56 lpul-k8stestwrk09 kernel: [1779317.170920] audit: type=1326 audit(1662053996.821:272): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=801989 comm="runc:[2:INIT]" exe="/" sig=0 arch=c000003e syscall=202 compat=0 ip=0x55ed9c8764f3 code=0x7ffc0000
Sep  1 10:39:56 lpul-k8stestwrk09 kernel: [1779317.170927] audit: type=1326 audit(1662053996.821:273): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=801989 comm="runc:[2:INIT]" exe="/" sig=0 arch=c000003e syscall=39 compat=0 ip=0x55ed9ca1c46b code=0x7ffc0000
...
```
We must then map the syscall id above, for example `syscall=35` using the `unistd_64.h` file  
**Note:** The asm folder did not exist on the test cluster node
```sh
grep -w 35 /usr/include/asm/unistd_64.h
```
output
```text
defina__NR_nanosleep 35
```
An easier way would be to get the syscall using `tracee` in Kubernetes  
This will provide the syscalls of all the new contianers on the host
```sh
docker run --name tracee --rm --privileged --pid=host \
  -v /lib/modules/:/lib/modules/:ro \
  -v /usr/src:/usr/src:ro \
  -v /tmp/tracee:/tmp/tracee \
  aquasec/tracee:0.4.0 --trace container=new
```
Output:  
The pod name is located under UTS_NAME column so we can `grep` for our pod name in the log  
The syscall is listed under the EVENT column
```text
TIME(s)        UTS_NAME         UID    COMM             PID/host        TID/host        RET              EVENT                ARGS
1780188.376384 test-audit       0      runc:[2:INIT]    1      /848117  1      /848117  0                execve               pathname: /usr/bin/bash, argv: [bash -c echo 'I just made some syscalls' && sleep 100]
1780188.376630 test-audit       0      runc:[2:INIT]    1      /848117  1      /848117  0                security_bprm_check  pathname: /usr/bin/bash, dev: 1789, inode: 1192553760
1780188.388974 test-audit       0      runc:[2:INIT]    1      /848117  1      /848117  0                cap_capable          cap: CAP_SYS_ADMIN
1780188.389006 test-audit       0      runc:[2:INIT]    1      /848117  1      /848117  0                cap_capable          cap: CAP_SYS_ADMIN
1780188.389015 test-audit       0      runc:[2:INIT]    1      /848117  1      /848117  0                cap_capable          cap: CAP_SYS_ADMIN
1780188.389023 test-audit       0      runc:[2:INIT]    1      /848117  1      /848117  0                cap_capable          cap: CAP_SYS_ADMIN
1780188.391193 test-audit       0      bash             1      /848117  1      /848117  -2               access               pathname: /etc/ld.so.preload, mode: R_OK
...
```
Now let's try a profile that rejects all syscalls
```sh
# Create the violation profile that will deny all syscalls
echo -e "{\n    \"defaultAction\": \"SCMP_ACT_ERRNO\"\n}" > /var/lib/kubelet/seccomp/profiles/violation.json
```
Create the pod that will use the violation seccomp profile
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-violation
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      # This path must be relative to k8s default seccomp profile which is stored in /var/lib/kubelet/seccomp/
      localhostProfile: profiles/violation.json
  nodeName: lpul-k8stestwrk09
  containers:
  - command: ["bash", "-c", "echo 'I just made some syscalls' && sleep 100"]
    image: ubuntu
    name: ubuntu
    securityContext:
      allowPrivilegeEscalation: false
  restartPolicy: Never
```
When looking at the above pod we will see a STATUS of either Error or ContainerCannotRun

Example detailed whitelist seccomp profile  
This is a whitelist profile because its default action is to block everything with `SCMP_ACT_ERRNO` then whielist what we need.  
Whitelist profiles are typically the most secure
```json
{
    "defaultAction": "SCMP_ACT_ERRNO",
    "architectures": [
        "SCMP_ARCH_X86_64",
        "SCMP_ARCH_X86",
        "SCMP_ARCH_X32"
    ],
    "syscalls": [
        {
            "names": [
                "accept4",
                "epoll_wait",
                "pselect6",
                "futex",
                "madvise",
                "epoll_ctl",
                "getsockname",
                "setsockopt",
                "vfork",
                "mmap",
                "read",
                "write",
                "close",
                "arch_prctl",
                "sched_getaffinity",
                "munmap",
                "brk",
                "rt_sigaction",
                "rt_sigprocmask",
                "sigaltstack",
                "gettid",
                "clone",
                "bind",
                "socket",
                "openat",
                "readlinkat",
                "exit_group",
                "epoll_create1",
                "listen",
                "rt_sigreturn",
                "sched_yield",
                "clock_gettime",
                "connect",
                "dup2",
                "epoll_pwait",
                "execve",
                "exit",
                "fcntl",
                "getpid",
                "getuid",
                "ioctl",
                "mprotect",
                "nanosleep",
                "open",
                "poll",
                "recvfrom",
                "sendto",
                "set_tid_address",
                "setitimer",
                "writev"
            ],
            "action": "SCMP_ACT_ALLOW"
        }
    ]
}
```

The following is a blacklist profile becuase its default action is to allow everything with `SCMP_ACT_ALLOW` then specify what we want blocked.
```json
{
    "defaultAction": "SCMP_ACT_ALLOW",
    "architectures": [
        "SCMP_ARCH_X86_64",
        "SCMP_ARCH_X86",
        "SCMP_ARCH_X32"
    ],
    "syscalls": [
        {
            "names": [
                "socket",
                "bind",
                "listen",
                "accept",
                "accept4",
                "connect",
                "shutdown",
                "setsockopt",
                "getsockopt"
            ],
            "action": "SCMP_ACT_ERRNO"
        }
    ]
}
```
## AppArmor

Instructions can be found in the k8s docs by searching for `apparmor`

Where `seccomp` restricts a programs access to system calls, it cannot restrict access to other objects such as a file or directory  
AppArmor is a linux security module which is used to restrict a program to a limited set of resources  
Check if AppArmor is installed:
```sh
systemctl status apparmor
```
To make use of AppArmor we must first make sure that the AppArmor kernel module is loaded on all the nodes that the container will be ran.
```sh
cat /sys/module/apparmor/parameters/enabled
```
Result
```text
Y
```
AppArmor uses profiles that must be loaded into the kernel  
We can check if they exist with  
```sh
cat /sys/kernel/security/apparmor/profiles
```
Example AppArmor profile:
```text
profile apparmor-deny-write flags-(attach_disconnected) {
  # "file," Allows complete access to the entire file system
  file,
  # Deny all file writes to the entire file system
  deny /** w,
}
```
Check AppArmor status
```sh
aa-status
```
Result
```text
apparmor module is loaded.
21 profiles are loaded.
20 profiles are in enforce mode.
   /sbin/dhclient
   /snap/core/13425/usr/lib/snapd/snap-confine
   /snap/core/13425/usr/lib/snapd/snap-confine//
   <truncated>
1 profiles are in complain mode.
   /usr/sbin/sssd
427 processes have profiles defined.
423 processes are in enforce mode.
   docker-default (3636)
   docker-default (4102159)
   docker-default (4102356)
   <truncated>
4 processes are in complain mode.
   /usr/sbin/sssd (1283)
   /usr/sbin/sssd (1467)
   /usr/sbin/sssd (1511)
   /usr/sbin/sssd (1512)
0 processes are unconfined but have a profile defined.
```
Profiles can be loaded in three different modes.
- `enforce`: Monitors and enforces the rules
- `complain`: Will allow the app to perform any tasks but logs them
- `unconfined`: Perform any tasks and does not log

Creating AppArmor Profiles

`add_data.sh` test script
```bash
#!/bin/bash
data_directory=/opt/app/data
mkdir -p ${data_directory}
echo "=> File created at `date`" | tee ${data_directory}/create.log
```
We will use the AppArmor tools to create profiles  
We must first install the AppArmor utils package  
```sh
apt-get install -y apparmor-utils
```
We can now use the `aa-genprof` tool to create the profile
```sh
aa-genprof /root/add_data.sh # must use absolute path to script
```
From a separate shell we must now run the bash script  
You will now be asked a series of permissions to determine what should be allowed and denied  
We can then view the created profile here  
```sh
cat /etc/apparmor.d/root.add_data.sh
```
Load an AppArmor profile  
```sh
apparmor_parser /etc/apparmor.d/root.add_data.sh
```
If nothing is written out it means it succeeded  
To disable a profile
```sh
apparmor_parser -R /etc/apparmor.d/root.add_data.sh
ln -s /etc/apparmor.d/root.add_data.sh /etc/apparmor.d/disable/
```
AppArmor in Kubernetes  
AppArmor was added in kubernetes 1.4 but is still in beta as of 1.20  
Requirements  
- AppArmor kernel module must be enabled on all the nodes that pods will run on
- AppArmor profile must be loaded on all the nodes
- Container runtime must support AppArmor (most support it, docker, containerd, etc.)
  
Example:  An Ubuntu pod that `echo`s a message and sleeps  
Since this pod does not write to the file system, let's use the `apparmor-deny-write` profile  
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: ubuntu-sleeper
  annotations:
    # Since this is still in beta we have to use the beta syntax
    # container.apparmor.security.beta.kubernetes.io/<pod-name>: localhost/<profile-name>
    container.apparmor.security.beta.kubernetes.io/ubuntu-sleeper: localhost/apparmor-deny-write
spec:
  containers:
  - name: hello
    image: ubuntu
    command: ["sh", "-c", "echo 'Sleeping for an hour!', && sleep 1h"]
```

## Add and Drop Linux Capabilities
Added in Linux Kernel 2.2

To check what capabilities an application needs we use the `getcap` command
```sh
getcap /usr/bin/ping
```
Output
```text
/usr/bin/ping = cap_net_raw+ep
```

To check the capabilties of a process we use the `getpcaps` command  
Get the pid of the ssh process
```sh
ps -ef | grep /usr/sbin/ssh
```
Output
```text
root        2626       1  0 Aug11 ?        00:00:00 /usr/sbin/sshd -D
```
Use the above id
```sh
getpcaps 2626
```
Output
```text
Capabilities for `2626': = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep
```

Add capabilities using `securityContext`: `capabilities`: `add`
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: ubuntu-sleeper
spec:
  containers:
  - name: ubuntu-sleeper
    image: ubuntu
    command: ["sleep","1000"]
    securityContext:
      capabilities:
        add: ["SYS_TIME"] # to add capabilities
        drop: ["CHOWN"] # to drop capabilities
```
We can now use this pod to change the date
```sh
k exec -it ubuntu-sleeper --bash
root@ubuntu-sleeper:/ date 
Sat Apr 3 05:32:06 UTC 2021
root@ubuntu-sleeper:/ date -s '19 APR 2012 22:00:00'
Sat Apr 3 05:32:06 UTC 2021
```
## Admission Controllers
Check which admission controllers are running
```sh
ps -ef | grep kube-apiserver | grep admission-plugins
```
Output
```text
. . . --enable-admission-plugins=NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,DefaultTolerationSeconds,MutatingAdmissionWebhook,ValidatingAdmissionWebhook,ResourceQuota,NodeRestriction,Priority,TaintNodesByCondition,PersistentVolumeClaimResize,PodSecurityPolicy . . .
```

To add an admission controller update the `--enable-admission-plugins` paramater where the `kube-apiserver` is configured.  We can also disable using the `--disable-admission-plugins`

Note that the `NamespaceExists` and `NamespaceAutoProvision` admission controllers are deprecated and now replaced by `NamespaceLifecycle` admission controller

The `NamespaceLifecycle` admission controller will make sure that requests to a non-existent namespace is rejected and that the default namespaces such as `default`, `kube-system` and `kube-public` cannot be deleted

### Creating our Own ACs

To facilitate the creation of custom ACs there are two built in ACs called `MutatingAdmissionsWebhook` and `ValidatingAdmissionWebhook`

Webhook processing takes place after all the other built in ACs  

#### Develop and Deploy a Webhook Service  

We need a service the webhook can call to evaluate the manifest file and reply with an allow or reject  
See the example [admission webhook server](https://github.com/kubernetes/kubernetes/blob/release-1.21/test/images/agnhost/webhook/main.go) written in Go   
More details in the [Dynamic Admission Control](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#write-an-admission-webhook-server) k8s documentation  
This can then be deployed as a deployment on the k8s cluster with a service or can be an external URL

#### Create a Validating Webhook Configuration Object

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
## Open Policy Agent
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
# example.rego
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

### OPA in Kubernetes

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
```js
// kubernetes.rego
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

When we install OPA into Kubernetes a sidecar called `kube-mgmt` is created in the OPA pod  
This side car loads Kubernetes objects so OPA knows what resources are deployed, it also loads `ConfigMap` policies into OPA that have labels of `openpolicyagent.org/policy: rego` as shown in the above example

## Container Sandboxing
### Container Sandboxing with gVisor

gVisor improves container isolation by inserting itself between the container and the kernel so syscalls go through gVisor

container --> syscall --> kernel  
becomes  
container --> syscall --> gVisor --> kernel  

gVisor has two components

- Sentry: acts as a kernel for containers 
- Gofer: A file proxy which impplements components needed for containers to talk to the file system
- gVisor has its own networking stack so the container does not need to interact with the host network

Each container has its own gVisor which isolates the containers from each other

Disadvantages of gVisor
- Not all apps work with gVisor
- Increases latency as there is more for the CPU to do

Whereas Docker uses `runC` as the base runtime, gVisor uses the `runsc` runtime to start containers

### Container Sandboxing with Kata Containers

Kata inserts each container into it's own light weight VM  
This does add some latency and increases resource usage  
Many cloud providers do not support Kata as it requires nested virtualization which is usually very poor  
Works well for bare metal servers

Whereas Docker uses `runC` as the base runtime, kata uses the `kata` runtime to start containers.

### Using Runtimes in Kubernetes

Assuming we have gVisor installed on Kubernetes how do we make use of it in K8s  
First we need to create a new k8s object called a `RuntimeClass` that details what handler will be used  

`gvisor.yaml`
```yaml
apiVersion: node.k8s.io/v1beta1
kind: RuntimeClass
metadata: 
  name: gvisor
handler: runsc
```
Install it  
```sh
k create -f gvisor.yaml
```
Now we can create a pod using the new RuntimeClass  
`nginx.yaml`
```yaml
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: nginx
  name: nginx
spec:
  runtimeClassName: gvisor
  containers:
  - image: nginx
    name: nginx
```
Create the pod
```sh
k create -f nginx.yaml
```
Check to make sure nginx is not running on the node
```sh
pgrep -a nginx
```
Confirm that runsc is running
```sh
pgrep -a runsc
```

## Static Analysis of User Workloads with `kubesec`

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
Command line usage  
```sh
kubesec scan k8s-deployment.yaml
# or
k get po grid-main-7bfb769655-2549s -o yaml | kubesec scan /dev/stdin | jq
```

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
trivy image --input nginx.tar

# Output of json to a directory
trivy image --format json --output /location/file nginx
```

## Falco
### Installation

**Method 1:** Install as a service directly on the node, this is the recommended way  
The advantage of installing Falco on the node as a service is that it is protected from container based attacks to a greater extent
```sh
curl -s https://falco.org/repo/falcosecurity-3672BA8F.asc | apt-key add -
echo "deb https://download.falco.org/packages/deb stable main" | tee -a /etc/apt/sources.list.d/falcosecurity.list
apt-get update -y

apt-get -y install linux-headers-$(uname -r)

apt-get install -y falco

# Check to make sure Falco is running
systemctl status falco
```

**Method 2:**  Install as a daemonset on the cluster
```sh
helm repo add falconsecurity https://falconsecurity.github.io/charts
helm repo add
helm install falco falcosecurity/falco
```

### Use Falco to Detect Threats

```sh
# run an image
k run nginx --image nginx

# in a separate terminal, run 
journalctl -fu falco

# Back on the first shell 
kubectl exec -it nginx -- bash

# On second shell, the logs will show 
# Notice A shell was spawned in a container with an attached terminal . . .

# Inside the container on terminal 1
cat /etc/shadow

# Logs
# Warning Sensitive file opened for reading by non-trusted program
```

### Falco Rules

```yaml
# rules.yaml
- rule: <name of the rule>
  desc: <Detailed Description of the rule>
  condition: <When to filter events matching the rule>
  output: <Output to be generated fo the event>
  priority: <Severity fo the event>
- rule: detect Shell inside a container
  desc: Alert if a shell such as bash is open inside the container
  condition: container.io !- host and proc.name = bash
  output: Bash Shell Opened (user=%user.name %container.id)
  priority: WARNING
```

#### Filters

In the above, the `container.name` and `proc.name` are Sysdig Filters  

Other common filters
- `fd.name`  Name of file descriptor.  To match events against a specific file
- `evt.type` Used to filter system calls by name
- `user.name` User tht took the action
- `container.image.repository` images by name

For more on Sysdig filters see https://falco.org/docs/rules/supported-fields/

#### Severity (Priority)

- DBUG
- INFORMATIONAL
- NOTICE
- WARNING
- ERROR
- CRITICAL
- ALERT
- EMERGENCY

Lists
```yaml
# Above we specified the bash shell, we can use a list instead  
- list: linux_shells
  items: [bash,zsh,ksh,sh,csh]
- rule: detect Shell inside a container
  desc: Alert if a shell such as bash is open inside the container
  condition: container.io !- host and proc.name in (linux_shells)
  output: Shell Opened (user=%user.name %container.id)
  priority: WARNING
```

Macros.  There are several macros that can be used when writing customer rules but we can also create our own
```yaml
- macro: container
  condition: container.id != host
- rule: detect Shell inside a container
  desc: Alert if a shell such as bash is open inside the container
  condition: container and proc.name in (linux_shells)
  output: Shell Opened (user=%user.name %container.id)
  priority: WARNING
```
Macro List: https://falco.org/docs/rules/default-macros/

### Falco Configuration Files

The main configuration file is at `/etc/falco/falco.yaml`  
This can be seen by viewing the service `systemctl status falco` or  
by viewing the falco logs `journalctl -u falco | grep configuration file`

```yaml
# /etc/falco/falco.yaml
# Rule order matters, later rule files with the same rule name will override earlier ones
rules_file:
 - /etc/falco/falco_rules.yaml
 - /etc/falco/falco_rules.local.yaml
 - /etc/falco/k8s_audit_rules.yaml
 - /etc/falco/rules.d

# Logs events in JSON if true
json_output: false

# Logging options for the falco process itself
log_stderr: true
log_syslog: true
log_level: info

# Minimum priority that falco will logs (for rules)
# Anything higher than this priority will be logged this and below will not
# debug means that every event will be logged by default
priority: debug

# Output channels (logging channels)
stdout_output: 
  enabled: true

# we can log events to a specific file 
file_output:
  enabled: true
  filename: /opt/falco/events.txt

# To send events to an external program such as a Slack webhook
program_output:
  enabled: true
  program: "jq '{text: .output}' | curl -d @- -X POST https://hooks.slack.com/services/XXX"

# An http endpoint
http_output:
  enabled: true
  url: http://some.url/some/path/

# There are more in the falco config file 
```
Reference Docs for configuration: https://falco.org/docs/configuration/

#### Rules

The `/etc/falco/falco_rules.yaml` file is where the main rule set is, it should not be modified as modifications will be overwritten when Falco is updated  
If you'd like to modify a default rule make a copy of it to the the `/etc/falco/falco_rules.local.yaml` file  
Store new custom rules in the same file `/etc/falco/falco_rules.local.yaml`

Once rules are edited or added we need to restart the Falco engine  

To Hot Reload the Falco configuration without restarting the Falco service we can issue a `kill -1` to the Falco pid  
```sh
kill -1 $(cat /var/run/falco.pid)
```

## Ensure Immutability of Containers at Runtime

### `readOnlyRootFilesystem`

Set the file system of the container to read only to prevent changes during runtime  
```yaml
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: nginx
  name: nginx
spec:
  containers:
  - image: nginx
    name: nginx
    securityContext:
      readOnlyRootFilesystem: true
```
This will cause NGINX to fail as it needs to write to certain files  
The solution is to mount `emptyDir` volumes to the paths that need written to  
```yaml
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: nginx
  name: nginx
spec:
  containers:
  - image: nginx
    name: nginx
    securityContext:
      readOnlyRootFilesystem: true
    volumeMounts:
    - name: cache-volume
      mountPath: /var/cache/nginx
    - name: runtime-volume
      mountPath: /var/run
   volumes:
   - name: cache-volume
     emptyDir: {}
   - name: runtime-volume
     emptyDir: {}     
```

### `privileged: true` Breaks Immutability

If `privileged: true` is set on a container with `readOnlyRootFilesystem: true` most of the file system is still immutable, however the `/proc/` file system is writable  
An attacher could `echo '75' > /proc/sys/vm/swappiness` and modify swappiness for both the container AND the host  


## Use Audit Logs to Monitor Access

The `kube-apiserver` handles auditing out of the box but it is not enabled by default 

`kube-apiserver` requests go through the following stages  
1. RequestReceived: After receive before any work
1. ResponseStarted: Applicable to long running tasks like `watch`
1. ResponseComplete: When all requested data is sent
1. Panic: If there was an error

We can manage what is recorded with audit policies
audit-policy.yaml
```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: ["RequestReceived"] # Optional
rules: 
  - namespace: ["prod-namespace"] # Optional
    verbs: ["delete"] # Optional
    resources: 
    - groups: " "
      resources: ["pods"]
      resourceName: ["webapp-pod"] # Optional
    level: RequestResponse # None, Metadata, Request, RequestResponse
  - level: Metadata
    resources:
    - groups: " "
      resources: ["secrets"]
```

## Enable Auditing

Two types of backends are supported  
- Log backend: Stores files locally on disk
- Webhook backend:  Makes use of a remote backend such as a Falco service

To enable auditing we have to pass the following commands into the `kube-apiserver`  
```yaml
- --audit-log-path=/var/log/k8s-audit.log # location of the audit log
- --audit-policy-file=/etc/kubernetes/audit-policy.yaml # Our policy file we created above
- --audit-log-maxage=10 # in days
- --audit-log-maxbackup=5 # number of files to retain on the host
- --audit-log-maxsize=100 # Max size of file in megabytes before being rotated
```
**NOTE:** Don't forget that when pointing to file locations as we do above that you must mount those paths as volumes if the source files are on the host