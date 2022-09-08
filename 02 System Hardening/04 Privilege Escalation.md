# Privilege Escalation

Use `sudo` for tasks require root privileges
```sh
# use sudo
sudo apt install nginx

# Only users in the /etc/sudoers file can use sudo
visudo
# Add user

# Set the root user to a no login shell
usermod -s /bin/nologin root
```

## Sudoers File Syntax

```sh
# Example sudoers file
# Root user, full access
root ALL=(ALL:ALL) ALL

# Admin group, full access
%admin ALL=(ALL:ALL) ALL

# allow sarah to shut down the server
sarah localhost=/usr/bin/shutdown -r now
```
Fields for above

1. User or %group
2. Hosts: localhost, ALL(default), almost always ALL
3. (User:Group): Almost always (ALL:ALL), optional
4. Command: ALL(default) or list of commands '/bin/ls'