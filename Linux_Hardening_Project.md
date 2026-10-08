# Linux Hardening Project

A homelab project where I took a deliberately misconfigured Ubuntu server (`zeus`), identified the security weaknesses, fixed them, and documented the risk and remediation for each one in the same way I would in a real environment.

The work covered two areas: operating system hardening (file permissions, accounts, authentication, environment settings) and network hardening (host firewall, exposed services, SSH configuration). I found 15 issues in total, 9 on the OS side and 6 on the network side.

**Tools used:** ufw, iptables, ss, sysctl, chmod, chown, passwd, getfacl/setfacl, grep, awk, find, dpkg, sshd, and the standard Linux command line.

---

## Overview

The most serious problems were the ones that would let any low-privileged local user become root: a world-writable `/etc/passwd`, and a `/bin/bash` that was both world-writable and had the SUID bit set. A blank root password and a world-readable `/etc/shadow` made the situation worse by weakening authentication and exposing credential material. On the network side, the host firewall was inactive and SSH, FTP and Samba were reachable from any address, which gave a much larger attack surface than the machine needed.

Several of these issues together (a spoofed `ls`, `/tmp` at the front of the PATH, writable account files, a SUID shell) look like deliberate tampering. On a real system I would not just fix the settings. I would also investigate for signs of compromise, and rebuild the host from a trusted image if its integrity could not be confirmed.

**Findings by severity**

- Critical (3): world-writable /etc/passwd, world-writable /bin/bash, SUID bit on /bin/bash
- High (8): fake ls binary, /tmp in PATH, readable /etc/shadow, no root password, firewall inactive, FTP exposed, Samba exposed, SSH root login enabled
- Medium (3): weak umask, SSH open to all addresses, SSH password authentication
- Low (1): core dumps

Severity is my own judgement, based on how easy the issue is to exploit, what access is needed, and the impact on confidentiality, integrity and availability.

---

## Scope and Approach

**In scope:** local OS configuration (permissions, accounts, authentication, kernel settings, shell environment) and network configuration (ufw/iptables, listening services, SSH daemon settings).

**Not covered:** patch level or package vulnerability scanning, application-layer testing of Samba/FTP/SSH, log forensics, and testing the firewall from an external machine.

**How I worked:** I enumerated the system with standard commands (`ls -l`, `which`, `echo $PATH`, `umask`, `passwd -S`, `sysctl`, `iptables -L`, `ufw status`, `ss -tulpn`, `grep` on `sshd_config`), recorded what I found, worked out the risk, applied the fix, and re-checked the result. My recommendations follow general CIS Benchmark style hardening and least privilege. Where it fits, I've mapped issues to MITRE ATT&CK techniques.

---

## Part 1: OS Hardening

### 1. Fake `ls` binary

**Severity:** High
**MITRE ATT&CK:** T1574.007 (Path Interception by PATH Environment Variable), T1036 (Masquerading)

**What I found:** Running `ls` returned an error saying `--color=auto` was an unrecognised option, which the real GNU `ls` supports. `which ls` showed the command resolving to `/usr/local/sbin/ls` instead of the system binary.

**Security impact:** `/usr/local/sbin` comes before `/bin` in the PATH, so the fake binary runs every time someone types `ls`. It could execute arbitrary code as whoever runs it (including an admin using sudo), hide files, or mislead users about the state of the system. This is a classic command spoofing and persistence technique.

**Fix:** Removed the fake binary.

```bash
sudo rm -rf /usr/local/sbin/ls
```

**Recommended improvements:**
- Preserve the file before deleting it: run `file` and `sha256sum` on it and copy it to a restricted folder for analysis. Use plain `rm` rather than `rm -rf` for a single file.
- Run `hash -r` and `type -a ls` to confirm the real binary is now used.
- Verify the legitimate package hasn't been altered with `dpkg -V coreutils`.
- Check `/usr/local/bin` and `/usr/local/sbin` for any other unexpected executables, and look at timestamps and ownership.
- Try to work out how it got there (auth.log, shell history).

### 2. `/tmp` at the front of the PATH

**Severity:** High
**MITRE ATT&CK:** T1574.007 (Path Interception by PATH Environment Variable)

**What I found:** `echo $PATH` showed `/tmp` as the very first entry.

**Security impact:** Every user can write to `/tmp`. Anyone could drop an executable there named after a common command (`ls`, `cat`, `sudo`), and it would run instead of the real one the next time someone calls it. If the victim is an administrator, this leads to privilege escalation.

**Fix:** Remove `/tmp` from the PATH, at the place it's being set:

```bash
grep -n "PATH" ~/.bashrc ~/.profile ~/.bash_profile /etc/environment /etc/profile
grep -rn "PATH" /etc/profile.d/
```

Then `source ~/.bashrc` and confirm with `echo $PATH`.

**Recommended improvements:**
- The PATH should only contain directories that are owned by root and not world-writable, with no `.` or empty entries.
- Check the PATH for root and any service accounts too.
- Look in `/tmp` for executables named like system commands.

### 3. World-writable `/etc/passwd`

**Severity:** Critical
**MITRE ATT&CK:** T1136.001 (Create Account: Local Account), T1098 (Account Manipulation)

**What I found:** `/etc/passwd` had permissions `-rw-rwxrw-+`, so group and others could write to it. The correct permission is 644.

**Security impact:** `/etc/passwd` defines every account, its UID/GID, home directory and shell. If any user can write to it, they can add a new account (including one with UID 0, which is root), change another user's shell or UID, or remove password placeholders. That is immediate and persistent privilege escalation, and a complete loss of account integrity.

**Fix:** Restored the permissions to 644, owned by root.

```bash
sudo chown root:root /etc/passwd
sudo chmod 644 /etc/passwd
```

Afterwards it showed `-rw-r--r--`.

**Recommended improvements:**
- Because the file was writable, audit it for accounts that shouldn't be there. `awk -F: '$3==0 {print $1}' /etc/passwd` lists UID 0 accounts, and `sudo pwck` checks the file for problems.
- Review auth.log for account creation or modification events.
- There is still a `+` after the permissions even after my fix, which means an ACL is attached. Check with `getfacl /etc/passwd` and remove it with `sudo setfacl -b /etc/passwd` if it isn't meant to be there.
- Use file integrity monitoring (AIDE or auditd watch rules) on `/etc/passwd`, `/etc/shadow`, `/etc/group` and `/etc/sudoers`.

### 4. World-readable `/etc/shadow`

**Severity:** High
**MITRE ATT&CK:** T1003.008 (OS Credential Dumping: /etc/passwd and /etc/shadow), T1110.002 (Password Cracking)

**What I found:** `/etc/shadow` was `-rw-r--r--` (root:shadow), so every local user could read the password hashes. It should be 640.

**Security impact:** Any user could copy all the hashes and crack them offline, with no lockouts, no rate limiting and no logging. Weak or reused passwords would be recovered quickly, giving the attacker valid credentials, possibly for privileged accounts or for other systems where the password is reused.

**Fix:**

```bash
sudo chmod 640 /etc/shadow
```

Now it shows `-rw-r----- root shadow`.

**Recommended improvements:**
- Confirm ownership is `root:shadow`.
- Treat all password hashes as exposed and force a password reset for every account, starting with privileged ones.
- Enforce a stronger password policy (`libpam-pwquality`, ageing settings in `/etc/login.defs`).
- Check whether any of the exposed passwords are reused elsewhere.

### 5. Weak umask

**Severity:** Medium

**What I found:** `umask` returned `0000`.

**Security impact:** No permission bits are removed from new objects, so new files are created as 666 and new directories as 777. Anything a user, script or application creates is readable and writable by every other local user, which risks data exposure and makes it easier to tamper with other people's files.

**Fix:** Set the umask to 022 in `~/.bashrc` and reloaded it.

```bash
nano ~/.bashrc
source ~/.bashrc
umask
```

It now returns `0022`.

**Recommended improvements:**
- This only covers my own user. A system-wide default should be set in `/etc/login.defs` (`UMASK`), `/etc/profile` and via `pam_umask`.
- On a stricter server, use `027` so that other users get no access at all.
- Look for world-writable files created while the weak umask was in effect: `find / -xdev -type f -perm -0002 2>/dev/null`.

### 6. World-writable `/bin/bash`

**Severity:** Critical
**MITRE ATT&CK:** T1548.001 (Setuid and Setgid)

**What I found:** `/bin/bash` was `-rwsrwxrwx` (root:root), so any user could modify it. The standard permission is 755.

**Security impact:** Any user could overwrite the default shell binary. Because it's owned by root and had SUID set, a modified copy would run with root privileges the next time it was started by a user, a cron job or a service. That is a direct route to full compromise, and a persistent backdoor.

**Fix:**

```bash
sudo chmod 755 /bin/bash
```

Now it shows `-rwxr-xr-x root root`.

**Recommended improvements:**
- Check the binary against its package (`dpkg -V bash` or `debsums -s bash`) and reinstall it if anything doesn't match (`sudo apt install --reinstall bash`).
- Search for other world-writable system binaries: `find /bin /sbin /usr/bin /usr/sbin /usr/local -xdev -perm -0002 -type f`.
- Use file integrity monitoring on core binaries.

### 7. SUID bit on bash

**Severity:** Critical
**MITRE ATT&CK:** T1548.001 (Setuid and Setgid)

**What I found:** `/bin/bash` was `-rwsr-xr-x`, so the SUID bit was set on a root-owned shell.

**Security impact:** A SUID-root shell lets any local user start a shell with root's effective privileges. No exploit or credentials are needed, so it's trivial, complete privilege escalation. Attackers commonly set this to keep access after getting temporary root.

**Fix:**

```bash
sudo chmod u-s /bin/bash
```

**Recommended improvements:**
- Audit all SUID/SGID files and compare them to what's expected for the distribution:
  ```bash
  sudo find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -ls 2>/dev/null
  ```
- Findings 6 and 7 appeared together on the same file, so I treat them as a possible sign of deliberate tampering and include them in the compromise checks at the end.
- Set up an auditd rule or scheduled check that alerts when new SUID/SGID files appear.

### 8. No password on root

**Severity:** High
**MITRE ATT&CK:** T1078.003 (Valid Accounts: Local Accounts)

**What I found:** `sudo passwd -S root` showed `NP`, meaning no password is set.

**Security impact:** Depending on the PAM and service configuration, an empty root password can allow passwordless authentication to root through local login or `su`. Even where remote login is blocked, this removes a layer of defence and raises the impact of every other misconfiguration on the system.

**Fix:** Set a strong password.

```bash
sudo passwd root
```

**Recommended improvements:**
- If admins use sudo, lock the root password completely with `sudo passwd -l root`.
- Check PAM for `nullok` in `/etc/pam.d/common-auth` and remove it so accounts with empty passwords can't authenticate.
- Look for any other blank-password accounts: `sudo awk -F: '$2=="" {print $1}' /etc/shadow`.
- Re-check with `sudo passwd -S root`, which should show `P` or `L`.

### 9. Core dumps enabled

**Severity:** Low

**What I found:** `kernel.core_pattern` was set to pass crashes to apport (`|/usr/share/apport/apport ...`), so crashing processes were being captured system-wide.

**Security impact:** A core dump is a snapshot of a process's memory and can contain credentials, session tokens, private keys or other sensitive data. If the dump files are stored with loose permissions or sent off the host, that data could be exposed. The risk here is low but it's a common hardening item.

**Fix:**

```bash
sudo sysctl -w kernel.core_pattern="|/bin/false"
```

**Recommended improvements:**
- That change disappears on reboot. To make it permanent:
  ```bash
  echo 'kernel.core_pattern=|/bin/false' | sudo tee /etc/sysctl.d/60-disable-coredump.conf
  echo 'fs.suid_dumpable=0' | sudo tee -a /etc/sysctl.d/60-disable-coredump.conf
  sudo sysctl --system
  ```
- Add `* hard core 0` to `/etc/security/limits.conf` to stop per-user core files.
- Trade-off: you also lose crash reporting, which may matter on a development machine. In that case, keep dumps but restrict where they're stored and how long they're kept.

---

## Part 2: Network Hardening

I started with `sudo iptables -L`. The INPUT policy was DROP, but there were rules accepting SSH (22), FTP (21), NetBIOS (139), SMB (445) and ICMP from anywhere. FORWARD was DROP and OUTPUT was ACCEPT. UFW, the tool meant to manage the firewall, wasn't running, so these rules weren't being managed as a proper policy.

### 1. Host firewall (UFW) inactive

**Severity:** High

**What I found:** `sudo ufw status` returned `Status: inactive`.

**Security impact:** Without a managed firewall, access to services isn't controlled by a defined, auditable policy. The only filtering was a loose set of raw iptables rules that can be lost or changed, and any service started later could end up exposed by accident.

**Fix:**

```bash
sudo ufw enable
```

Status now shows active.

**Recommended improvements:**
- Set the default policies explicitly (deny incoming, allow outgoing).
- Turn on logging (`sudo ufw logging on`) and send the logs to a central place.
- If you're working over SSH, add the SSH rule before enabling the firewall so you don't lock yourself out.

### 2. SSH open to everyone

**Severity:** Medium
**MITRE ATT&CK:** T1021.004 (Remote Services: SSH), T1110 (Brute Force)

**What I found:** Port 22 was accepted from any source address.

**Security impact:** SSH facing everyone gets constant automated brute-force and credential stuffing attempts, and it widens the attack surface to any future SSH vulnerability.

**Fix:** Used UFW's rate limiting.

```bash
sudo ufw limit ssh
```

This still allows SSH, but blocks an address that makes 6 or more connections in 30 seconds.

**Recommended improvements:**
- Only allow SSH from known management IPs or a VPN/bastion host: `sudo ufw allow from <trusted-ip-or-range> to any port 22 proto tcp`.
- Use key-based login and disable root login (items 5 and 6 below).
- Consider fail2ban and `MaxAuthTries 3`, and monitor auth.log for repeated failures.

### 3. FTP exposed

**Severity:** High
**MITRE ATT&CK:** T1040 (Network Sniffing)

**What I found:** Port 21 was open to any IP.

**Security impact:** FTP sends usernames, passwords and files in plain text. Anyone who can see the traffic can capture them. Exposed FTP is also a common target for brute force and anonymous access attacks.

**Fix:**

```bash
sudo ufw deny 21/tcp
```

**Recommended improvements:**
- Blocking the port doesn't stop the service. Find what's running with `sudo ss -tlnp | grep :21` and disable it: `sudo systemctl disable --now <service>`.
- Use SFTP (over SSH) or FTPS if file transfer is actually needed.
- Remove the package completely if it isn't needed.

### 4. Samba exposed

**Severity:** High
**MITRE ATT&CK:** T1021.002 (Remote Services: SMB/Windows Admin Shares)

**What I found:** `ss -tulpn | grep 445` showed port 445 listening on all interfaces (`0.0.0.0:445` and `[::]:445`), and the iptables rules also accepted port 139 from anywhere.

**Security impact:** SMB exposed beyond the trusted LAN is a major risk. It has a history of serious vulnerabilities and wormable malware, and it's a common route for credential attacks and lateral movement.

**Fix:** Restricted Samba to my local subnet only.

```bash
sudo ufw allow from 10.130.144.0/24 to any app Samba
```

**Recommended improvements:**
- Bind Samba to the internal interface only (`interfaces` and `bind interfaces only = yes` in `smb.conf`).
- Set a minimum SMB protocol version, require signing, and disable guest access.
- Remove Samba entirely if file sharing isn't needed, and keep it patched.
- When I checked `ufw status numbered` afterwards, there was a rule `Anywhere ALLOW IN 10.130.144.0/24`, which lets the whole LAN reach every port, plus duplicate Samba rules. That's too broad, so I'd reset and rebuild using the script at the end.

### 5. SSH root login enabled

**Severity:** High
**MITRE ATT&CK:** T1021.004 (Remote Services: SSH), T1078.003 (Valid Accounts: Local Accounts)

**What I found:** `grep PermitRootLogin /etc/ssh/sshd_config` showed `PermitRootLogin yes`, overriding the commented-out safe default (`prohibit-password`).

**Security impact:** Anyone can SSH straight in as root. The username is known in advance, so it's a constant brute-force target, an attacker only needs one credential for full control, and you lose accountability because actions can't be tied to a named admin.

**Fix:** Set it to `no`, test the config and reload.

```bash
sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sshd -t && sudo systemctl reload ssh
```

**Recommended improvements:**
- Make sure a named admin account with sudo can log in before applying this, and keep an existing session open while testing.
- Check `/etc/ssh/sshd_config.d/*.conf`, since drop-in files can override the main config.
- Confirm the effective value with `sudo sshd -T | grep permitrootlogin`.

*Status: fix defined, but I didn't capture it being applied.*

### 6. SSH password authentication enabled

**Severity:** Medium
**MITRE ATT&CK:** T1110 (Brute Force), T1021.004 (Remote Services: SSH)

**What I found:** Password login was enabled for SSH.

**Security impact:** Passwords can be guessed, sprayed, or reused from other breaches. Key-based authentication isn't exposed to online password guessing and is much stronger.

**Fix:** Set up key-based login first, then set this in `sshd_config`:

```
PasswordAuthentication no
```

Test and reload with `sudo sshd -t && sudo systemctl reload ssh`.

**Recommended improvements:**
- Test the SSH keys (`ssh-copy-id`) before turning off passwords, to avoid a lockout.
- Protect private keys with a passphrase, and consider hardware keys or MFA.
- Also set `PermitEmptyPasswords no` and `MaxAuthTries 3`, and verify with `sudo sshd -T`.

*Status: fix defined, but I didn't capture it being applied.*

---

## Remaining Items

These came up when I looked back over my final outputs.

- **ACL on `/etc/passwd`:** the `+` is still there after the fix. Inspect with `getfacl` and remove it if unintended. Check `/etc/shadow`, `/etc/sudoers` and `/bin/bash` for ACLs too.
- **Broad UFW rule:** the allow-all-ports rule from the LAN and the duplicate Samba rules should be cleaned up. The script at the end does this.
- **Core dump setting:** applied with `sysctl -w`, so it needs to be made permanent.
- **Old iptables rules:** confirm with `sudo iptables -S` and `sudo ufw status verbose` that no old permissive rules are left behind once UFW is on.
- **ICMP:** allowed from anywhere. Fine for diagnostics, but could be limited to trusted ranges.

---

## Remediation Priorities

If I were doing this on a real system, this is the order I'd work in.

**Straight away**
1. Check for signs of compromise: review `/etc/passwd`, `/etc/group`, `/etc/sudoers` and `sudoers.d`, `authorized_keys` files, cron jobs, systemd units, auth.log and shell history. If integrity can't be confirmed, rebuild from a trusted image.
2. Reset all local passwords, since `/etc/shadow` was readable.
3. Verify package integrity (`debsums` / `dpkg -V`) and reinstall `bash` and `coreutils` if anything doesn't match.
4. Apply the SSH fixes once key-based admin access is confirmed.
5. Clear up the remaining items above.

**Within a couple of weeks**
6. Make all runtime changes permanent and set a system-wide umask.
7. Disable and remove FTP, and bind Samba to the internal interface or remove it.
8. Turn on UFW logging and send auth, firewall and auditd logs to a central place.
9. Run a full SUID/SGID and world-writable file audit against a baseline.

**Longer term**
10. File integrity monitoring (AIDE or auditd) on `/etc`, `/bin`, `/usr/bin` and `/usr/local`.
11. Regular compliance scanning (CIS, Lynis or OpenSCAP) to catch configuration drift.
12. A standard hardened build, applied with configuration management.
13. Patch management and scheduled vulnerability scans.
14. Least privilege for sudo, named admin accounts, and MFA for remote admin access.

---

## Hardened UFW Rules

A clean set of firewall rules. If you're on a remote machine, keep a second SSH session open while you do this.

```bash
# 1. Reset UFW to a clean starting point
sudo ufw --force reset

# 2. Default policies: deny all incoming, allow all outgoing
sudo ufw default deny incoming
sudo ufw default allow outgoing

# 3. Limit SSH (port 22) to add brute-force protection
sudo ufw limit ssh

# 4. Explicitly deny FTP (port 21)
sudo ufw deny 21/tcp

# 5. Restrict Samba to the local LAN subnet
sudo ufw allow from 10.130.144.0/24 to any app Samba

# 6. Enable the firewall
sudo ufw --force enable

# 7. Check the final rules
sudo ufw status numbered
```

---

## Verification Checks

Quick commands to confirm everything is fixed.

```bash
type -a ls                                   # only the real ls
echo $PATH                                   # no /tmp or . in it
ls -l /etc/passwd; getfacl /etc/passwd       # 644 root:root, no stray ACL
ls -l /etc/shadow                            # 640 root:shadow
umask                                        # 0022 or stricter
ls -l /bin/bash                              # -rwxr-xr-x, no "s"
sudo passwd -S root                          # P (set) or L (locked)
sysctl kernel.core_pattern fs.suid_dumpable  # |/bin/false and 0
sudo ufw status verbose                      # active, default deny incoming
sudo sshd -T | grep -Ei 'permitrootlogin|passwordauthentication'
```

---

## What I Learned

- Small permission mistakes on files like `/etc/passwd`, `/etc/shadow` and `/bin/bash` can hand over full control of a system.
- Looking at the PATH and `which` output can quickly reveal a spoofed binary.
- A firewall should default to deny, with only the required services allowed and ideally only from trusted addresses.
- Blocking a port isn't the same as turning off the service behind it.
- Several small issues can chain together into a much bigger one, so it's worth thinking about attack paths and not just individual settings.
- Always verify a fix afterwards, and keep a second way in before changing SSH settings.

**Skills practised:** Linux hardening, file permission and privilege auditing, authentication and credential hygiene, firewall design with UFW/iptables, SSH hardening, attack surface reduction, risk rating, MITRE ATT&CK mapping, and technical documentation.
