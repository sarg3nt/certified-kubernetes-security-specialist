# Docker Service

## Basic Configuration

```sh
# Running as a service
systemctl start docker
systemctl status docker
systemctl stop docker

# Manually, typically for troubleshooting
dockerd
# Debug flag
dockerd --debug

# Listens on the Unix socket
/var/run/docker.sock
# this allows internal communication only, which is the default
# To add external access to the Docker daemon, port 2375 is the standard Docker port
dockerd --debug --host=tcp://192.168.1.10:2375
# We could now talk to this Docker host remotely by setting the env var
export DOCKER_HOST="tcp://192.168.1.10:2375"
# NOTE: There is a reason this is disabled by default as it is very insecure, no encryption or authentication
# Never do this on a publicly available host

# To enable encryption, create a certificate and turn it on like this:  
# 2376 is the standard encrypted traffic port
dockerd --debug \
  --host=tcp://192.168.1.10:2376 \
  --tls=true \
  --tlscert=/var/docker/server.pem \
  --tlskey=/var/docker/serverkey.pem
```

The config above could be moved to the docker configuration file: `/etc/docker/daemon.json`  
This is the same file used by `systemctl` to run the service
```json
 {
   "debug": true,
   "hosts": ["tcp://192.168.1.10:2376"],
   "tls": true,
   "tlscert": "/var/docker/server.pem",
   "tlskey": "/var/docker/serverkey.pem"
 }
```

## Securing the Docker Daemon

What are the problems with someone gaining access to Docker

- Can delete existing containers
- Can delete volumes that have application data
- Can run their own containers (bit coin mining, attack tools)
- Can gain root access to the host system itself by running a privileged container

Best practice is to not expose the Docker Daemon to the outside world at all, which is the default, however we may run into a situation where it is necessary to expose docker over TCP, here are some things that should be done to protect it

- Only expose on an interface that is part of your private network, i.e. not on public interfaces.
- Secure communication with TLS certs.  See config in earlier sections
- Enable Authentication

## Enable Encryption

### Docker Service

Create a Certificate pair and use it for encryption.

```json
 {
   "hosts": ["tcp://192.168.1.10:2376"],
   "tls": true,
   "tlscert": "/var/docker/server.pem",
   "tlskey": "/var/docker/serverkey.pem"
 }
```

### Docker Client

Set vars to point at the correct location and turn on TLS

```sh
export DOCKER_HOST="tcp://192.168.1.10:2376"
docker --tls ps
# OR
export DOCKER_TLS=true
docker ps
```

**Note:** Anyone can still communicate to the docker daemon as there is no authentication yet, just encryption

## Enable Authentication

This requires a CA to create certs.  Any certificates created by that CA would be able to connect to Docker on the server configured to use it.

### Server
Copy the CA cert to the Docker server and configure the daemon to use it

```json
{
  "hosts": ["tcp://192.168.1.10:2376"],
  "tls": true,
  "tlscert": "/var/docker/server.pem",
  "tlskey": "/var/docker/serverkey.pem",
  "tlsverify": true, // This enables authentication
  "tlscacert": "/var/docker/caserver.pem" // Docker will use this ca cert to verify those that connect
}
```

### Client

Create a certificate pare using the same CA the server is using and copy them to the client along with the CA cert

```sh
export DOCKER_HOST="tcp://192.168.1.10:2376"
export DOCKER_TLS_VERIFY=true # Different flag than above!
# Specify all the certs in each command
docker --tlscert=<> --tlskey=<> --tlscacer=<> ps
# OR, drop the certs into the users home docker dir
cp <certs> ~/.docker/
docker ps
```