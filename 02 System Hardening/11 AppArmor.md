# AppArmor

Instructions can be found in the k8s docs by searching for `apparmor`

Used to restrict an applications capabilities to further reduce the attack surface of a threat

Where `seccomp` restricts a programs access to system calls, it cannot restrict access to other objects such as a file or directory

AppArmor is a linux security module which is used to restrict a program to a limited set of resources

AppArmor is installed in most Linux distributions  
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

## Creating AppArmor Profiles

We have a custom bash script that creates files under the `opt` directory and then writes to a log file  
This bash script will be called `add_data.sh`
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

## AppArmor in Kubernetes

AppArmor was added in kubernetes 1.4 but is still in beta as of 1.20

Requirements
- AppArmor kernel module must be enabled on all the nodes that pods will run on
- AppArmor profile must be loaded on all the nodes
- Container runtime must support AppArmor (most support it, docker, containerd, etc.)
  
### Example 1

An Ubuntu pod that `echo`s a message and sleeps  
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
