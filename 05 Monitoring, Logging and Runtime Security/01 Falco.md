# Falco

## Architecture

1. Falco can use either a custom Falco Kernel module or the eBPF (extended Burkley Packet Filter)  
Most cloud providers do not allow the installation of the Falco Kernel module but do allow eBPF
1. The system calls are then analyzed by the SysDig libraries in User Space
1. Events are then filtered by the Falco Policy Engine by making use of the pre-defined rules
1. Events are then sent via the various output channels (local file, webhook, etc.)



## Installation

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

## Use Falco to Detect Threats

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

## Falco Rules

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

### Filters

In the above, the `container.name` and `proc.name` are Sysdig Filters  

Other common filters
- `fd.name`  Name of file descriptor.  To match events against a specific file
- `evt.type` Used to filter system calls by name
- `user.name` User tht took the action
- `container.image.repository` images by name

For more on Sysdig filters see https://falco.org/docs/rules/supported-fields/

### Severity (Priority)

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

## Falco Configuration Files

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

### Rules

The `/etc/falco/falco_rules.yaml` file is where the main rule set is, it should not be modified as modifications will be overwritten when Falco is updated  
If you'd like to modify a default rule make a copy of it to the the `/etc/falco/falco_rules.local.yaml` file  
Store new custom rules in the same file `/etc/falco/falco_rules.local.yaml`

Once rules are edited or added we need to restart the Falco engine  

To Hot Reload the Falco configuration without restarting the Falco service we can issue a `kill -1` to the Falco pid  
```sh
kill -1 $(cat /var/run/falco.pid)
```
## References

- https://falco.org/docs/getting-started/installation/
- https://github.com/falcosecurity/charts/tree/master/falco
- https://falco.org/docs/rules/supported-fields/
- https://falco.org/docs/rules/default-macros/
- https://falco.org/docs/configuration/
