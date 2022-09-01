# Linux `syscalls` and `seccomp`

**Exam Tip:** The exam will probably not ask us to create a seccomp profile by hand but it probably weill ask us to copy an existing seccomp profile to the correct directory and use it in pods.

All seccomp related documentation can be found in the kubernetes docs by searching for `seccomp` which will lease here: https://kubernetes.io/docs/tutorials/security/seccomp/

System Calls consist of communication between user space where applications are run and Kernel Space.

Examples of system calls are open(), close(), execve(), readdir(), strlen(), closedir(), etc.

## `strace`

Determine what syscalls an application uses with `strace`

```sh
# strace is a tool used to trace system calls by an application
/usr/bin/strace

# This provides a lot of detail
strace touch /tmp/error.log
# execve("/usr/bin/touch", ["touch", "/tmp/error.log"], 0x7ffdb5aef278 /* 40 vars */) = 0

# to trace a running process we need the pid
pidof etcd
# 3596

# Now use that pid to attach to the process with strace
strace -p 3596

# to see all syscals
strace -c touch /tmp/error.log
```
Results
```text
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
  0.00    0.000000           0         3           read
  0.00    0.000000           0        22           close
  0.00    0.000000           0        18           fstat
  0.00    0.000000           0        22           mmap
  0.00    0.000000           0         3           mprotect
  0.00    0.000000           0         1           munmap
  0.00    0.000000           0         3           brk
  0.00    0.000000           0         6           pread64
  0.00    0.000000           0         1         1 access
  0.00    0.000000           0         1           dup2
  0.00    0.000000           0         1           execve
  0.00    0.000000           0         2         1 arch_prctl
  0.00    0.000000           0        19           openat
  0.00    0.000000           0         1           utimensat
------ ----------- ----------- --------- --------- ----------------
100.00    0.000000                   103         2 total
```

## Aquasec Tracee

Used to trace system calls on containers

Tracee can be installed in the OS but it is often easier to run it as a Docker container.

```sh
# To trace "command" of "ls"
docker run --name tracee --rm --privileged --pid=host \
  -v /lib/modules/:/lib/modules/:ro \
  -v /usr/src:/usr/src:ro \
  -v /tmp/tracee:/tmp/tracee \
  aquasec/tracee:0.4.0 --trace comm=ls

# To trace all new pids on the host
docker run --name tracee --rm --privileged --pid=host \
  -v /lib/modules/:/lib/modules/:ro \
  -v /usr/src:/usr/src:ro \
  -v /tmp/tracee:/tmp/tracee \
  aquasec/tracee:0.4.0 --trace pid=new

# Trace all new containers
docker run --name tracee --rm --privileged --pid=host \
  -v /lib/modules/:/lib/modules/:ro \
  -v /usr/src:/usr/src:ro \
  -v /tmp/tracee:/tmp/tracee \
  aquasec/tracee:0.4.0 --trace container=new
```

## Restrict `syscalls` with `seccomp`

There are about 435 syscalls in Linux and all can be used by applications, however in reality, no application will need to make this many syscalls.  Having access to these syscalls can increase attack service.

In 2016 the Dirty Cow vulnerability used ptrace to write to a read only file, gain access to root and break out of the container

seccomp can be used to restrict syscalls.

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
UID        PID  PPID  C STIME TTY          TIME CMD
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

## seccomp in Kubernetes

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
  creationTimestamp: null
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

We can use a custom seccomp profile as well  
Create the seccomp profile
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

View the logs on the node at /var/log/syhslog
```sh
sudo grep syscall /var/log/syslog
```
Output
```text
Sep  1 10:39:56 lpul-k8stestwrk09 kernel: [1779317.170920] audit: type=1326 audit(1662053996.821:272): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=801989 comm="runc:[2:INIT]" exe="/" sig=0 arch=c000003e syscall=202 compat=0 ip=0x55ed9c8764f3 code=0x7ffc0000
Sep  1 10:39:56 lpul-k8stestwrk09 kernel: [1779317.170927] audit: type=1326 audit(1662053996.821:273): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=801989 comm="runc:[2:INIT]" exe="/" sig=0 arch=c000003e syscall=39 compat=0 ip=0x55ed9ca1c46b code=0x7ffc0000
Sep  1 10:39:56 lpul-k8stestwrk09 kernel: [1779317.170932] audit: type=1326 audit(1662053996.821:275): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=801989 comm="runc:[2:INIT]" exe="/" sig=0 arch=c000003e syscall=59 compat=0 ip=0x55ed9c8ca93b code=0x7ffc0000
Sep  1 10:39:56 lpul-k8stestwrk09 kernel: [1779317.170937] audit: type=1326 audit(1662053996.821:274): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=801989 comm="runc:[2:INIT]" exe="/" sig=0 arch=c000003e syscall=35 compat=0 ip=0x55ed9c875f5d code=0x7ffc0000
Sep  1 10:39:56 lpul-k8stestwrk09 kernel: [1779317.171044] audit: type=1326 audit(1662053996.821:276): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=801989 comm="runc:[2:INIT]" exe="/" sig=0 arch=c000003e syscall=35 compat=0 ip=0x55ed9c875f5d code=0x7ffc0000
Sep  1 10:39:56 lpul-k8stestwrk09 kernel: [1779317.171161] audit: type=1326 audit(1662053996.821:277): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=801989 comm="runc:[2:INIT]" exe="/" sig=0 arch=c000003e syscall=35 compat=0 ip=0x55ed9c875f5d code=0x7ffc0000
Sep  1 10:39:56 lpul-k8stestwrk09 kernel: [1779317.171253] audit: type=1326 audit(1662053996.821:278): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=801989 comm="runc:[2:INIT]" exe="/" sig=0 arch=c000003e syscall=35 compat=0 ip=0x55ed9c875f5d code=0x7ffc0000
Sep  1 10:39:56 lpul-k8stestwrk09 kernel: [1779317.171342] audit: type=1326 audit(1662053996.821:279): auid=4294967295 uid=0 gid=0 ses=4294967295 
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
<truncated>
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