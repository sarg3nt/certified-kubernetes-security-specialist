# Restrict Network Access To Servers

- Can apply these rules on network firewalls
- Can apply rules on the system firewall

# UFW Uncomplicated Firewall

The internal tool is called `netfiler`  
`iptables` is one of the most common interfaces to `netfilter` but it has a steep learning curve  
`ufw` is another interface to `netfilter` that many find much easier

## Install UFW
```sh
apt-get update
apt-get install ufw
systemctl enable ufw
systemctl start ufw

ufw status
# Status: inactive
```

## Using UFW
```sh
# See what ports are open
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