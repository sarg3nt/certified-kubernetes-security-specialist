# Limit Node Access

- It is best practice to limit the access to the nodes running Kubernetes.  
  The nodes should not be accessible from the Internet.
- Access nodes via VPN or via authorized networks in the infrastructure firewall
- To mitigate internal threats only those that need access to the nodes should have it

## Users

Types of Users

- User Accounts:  These are least privileged accounts for standard users
- Superuser Account:  Account with UID: 0, root
- System Accounts:  Accounts created by software that has been installed on the system but is not a service.  Examples: ssh, mail
- Service Accounts: Accounts created by software installed on the system that runs as a daemon / service.  Examples: nginx, http

To see details about users in Linux

```sh
# See data bout the current user
id
# uid=1000(davesarg) gid=1000(davesarg) groups=1000(davesarg),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),117(netdev),1001(docker)

# See who is currently logged into the system
who 

# See the last time users where logged into the system
last
```

## Access Control

Access control files are stored in `/etc`
```sh
# Stores basic information about the users in the system, username, uid, gid, home directory and default share.  It does not contain password.
/etc/passwd

# Stores passwords, is hashed
/etc/shadow

# Stores information about all the groups ont he system
/etc/group
```

We can use the above tools and directories to determine what a user has access to and change their access so they have the least privilege possible.

```sh
# Set user michael's shell to the nologin one so he can't log in
usermod -s /bin/nologin michael

# Check Michaels access
grep -i michael /etc/passwd
# michael:x:1001:1001::/home/michael:/bin/nologin

# Or, we could delete michael
userdel michael
```

Remove users from groups they do not need to be in
```sh
id michael
#uid=1001(michael) gid=1001(michael) groups=1001(michael),1000(admin)

# Remove Michael from the admin group
deluser michael admin

id michael
#uid=1001(michael) gid=1001(michael) groups=1001(michael)
```

**NOTE:** Above commands are for local accounts only and do not apply to Active Directory or LDAP

Other Linux commands
```sh
# Change another users password
passwd bob

# Delete a user
deluser ray

# Delete a group
delgroup devs

# Create a user with options
useradd \
  --home-dir /opt/sam \
  --shell /bin/bash \
  --uid 2328 \
  --groups admin \
  sam
```