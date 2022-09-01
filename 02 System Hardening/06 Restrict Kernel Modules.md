# Restrict Kernel Modules

The Linux kernel has a modular design which allows it to dynamically load kernel modules, such as adding device drivers for video cards.  
Modules can also be added manually.

```sh
# Add a module manually
modprobe pcspkr

# list all modules loaded
lsmod

# Note: Unprivileged Containers can cause modules to load into the kernel by creating a network socket

# Blacklist modules
# The sctp module is not commonly used
cat /etc/modprobe.d/blacklist.conf
blacklist sctp

# Then reboot node
shutdown -r now
# And confirm it is not listed
lsmod | grep sctp

# The dccp (datagram condition control protocol) is also not commonly used
blacklist dccp

# Refer to section 3.4 for more uncommon network protocols that can be blacklisted
```

