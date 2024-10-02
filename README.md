# KaliHarden By Taylor Christian Newsome

# Advanced Hardening Additions

Network Hardening (sysctl.conf): Implements kernel-level protections against spoofing, SYN flood attacks, and other network-based threats.

AppArmor: Enforces mandatory access control policies for applications.

ClamAV: Adds malware scanning capabilities.

AuditD: Enables auditing of system activities for detailed logs.

AIDE: Provides file integrity checking.

Firejail: Sandboxes applications to limit damage if they are compromised.

Fail2Ban: Configured to protect against SSH brute-force attacks.

Rootkit Detection (RKHunter, CHKRootkit): Detects rootkits and hidden security threats.

Strong Password Policies: Minimum length, complexity, and account lockout after failed login attempts.

SSH Security: Disables root login, disables password authentication, limits authentication retries, and disables unnecessary SSH features.

Including kernel, network, access, monitoring, and advanced intrusion detection

# Usage

To use the script, follow these steps

```bash
git clone https://github.com/SleepTheGod/KaliHarden
cd KaliHarden
chmod +x main.sh
chmod +x fix.sh
chmod +x install.sh
chmod +x iptables.sh
sudo bash main.sh; sudo bash fix.sh; sudo bash install.sh; sudo bash iptables.sh;
```

Run it with the desired options, for example

```bash
sudo ./harden.sh --kernel
```

You can use multiple options at once, like this

```bash
sudo ./harden.sh --kernel --network --ssh
```
