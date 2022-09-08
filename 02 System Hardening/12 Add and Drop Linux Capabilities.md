# Add and Drop Linux Capabilities

In Linux Kernel < 2.2 there were two types of processes.  Privileged Processes and Unprivileged processes.  Privileged processes were those ran by UID 0, the root user and they could do anything, bypassing the kernel checks.  

From Linux Kernel 2.2 onwards, the Privileged Process where broken up into a set of capabilities which can now be assigned to different applications

To check what capabilities an application needs we use the `getcap` command
```sh
getcap /usr/bin/ping
```
Output
```text
/usr/bin/ping = cap_net_raw+ep
```

To check the capabilties of a process we use the `getpcaps` command
```sh
# What are the capabilities of the ssh process?
# First we need the pid of the process
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