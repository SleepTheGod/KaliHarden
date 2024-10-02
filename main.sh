#!/bin/bash

# Advanced Security and Network Hardening Script for Kali Linux by Taylor Newsome
# Including kernel, network, access, monitoring, and advanced intrusion detection

# Ensure system is up-to-date
sudo apt-get update && sudo apt-get upgrade -y

########################
# Kernel-Level Hardening
########################

# Secure /etc/sysctl.conf - kernel parameters for system security
sudo cp /etc/sysctl.conf /etc/sysctl.conf.backup
cat <<EOF | sudo tee /etc/sysctl.conf

# Disable IP forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Enable SYN flood protection
net.ipv4.tcp_syncookies = 1

# Enable protection against IP spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP echo requests (ping flood protection)
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Log packets with impossible addresses
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Disable redirects to prevent MITM attacks
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Disable ICMP redirect acceptance
net.ipv4.conf.all.secure_redirects = 0
net.ipv6.conf.all.secure_redirects = 0

# Harden TCP against common attacks
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_window_scaling = 0
net.ipv4.conf.all.send_redirects = 0
EOF
sudo sysctl -p

# Restrict core dumps
echo "* hard core 0" | sudo tee -a /etc/security/limits.conf
sudo sysctl -w fs.suid_dumpable=0

# Disable unprivileged eBPF
sudo sysctl -w kernel.unprivileged_bpf_disabled=1

# Disable unprivileged user namespaces
sudo sysctl -w kernel.unprivileged_userns_clone=0

# Prevent kernel module loading
echo "kernel.modules_disabled = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

########################
# GRUB Hardening
# Protect Boot Loader
########################

# Password-protect GRUB (important for full security control)
sudo apt-get install -y grub-pc
echo "set superusers=\"root\"" | sudo tee -a /etc/grub.d/40_custom
echo "password_pbkdf2 root $(grub-mkpasswd-pbkdf2)" | sudo tee -a /etc/grub.d/40_custom
sudo update-grub

########################
# User & Access Control
########################

# Lock root account and enforce sudo
sudo passwd -l root
echo "Defaults rootpw" | sudo tee -a /etc/sudoers

# Strong password policies
sudo apt-get install -y libpam-cracklib
sudo cp /etc/pam.d/common-password /etc/pam.d/common-password.backup
echo "password requisite pam_cracklib.so retry=3 minlen=14 difok=4 ucredit=-1 dcredit=-1 ocredit=-1 lcredit=-1" | sudo tee -a /etc/pam.d/common-password
echo "auth required pam_tally2.so deny=5 onerr=fail unlock_time=900" | sudo tee -a /etc/pam.d/common-auth

# Enforce password aging policies
sudo cp /etc/login.defs /etc/login.defs.backup
sudo sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sudo sed -i 's/PASS_MIN_DAYS.*/PASS_MIN_DAYS   10/' /etc/login.defs
sudo sed -i 's/PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs

# Remove unnecessary user accounts
for USER in games news sync; do
    sudo userdel -r $USER
done

########################
# Network Hardening
########################

# Enable Uncomplicated Firewall (UFW)
sudo apt-get install -y ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp  # Allow HTTP if required
sudo ufw allow 443/tcp  # Allow HTTPS if required
sudo ufw enable

# Disable IPv6 if not needed
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1
sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1

########################
# Intrusion Detection
########################

# Install and configure Fail2Ban
sudo apt-get install -y fail2ban
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sudo systemctl enable fail2ban
sudo systemctl restart fail2ban

# Install and configure AppArmor
sudo apt-get install -y apparmor apparmor-profiles apparmor-utils
sudo systemctl enable apparmor
sudo systemctl start apparmor
sudo aa-enforce /etc/apparmor.d/*

# Install AIDE (Advanced Intrusion Detection Environment)
sudo apt-get install -y aide
sudo aideinit
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
sudo systemctl enable aidecheck.timer

# Install and configure SELinux (Mandatory Access Control)
sudo apt-get install -y selinux-basics selinux-policy-default auditd
sudo selinux-activate
sudo selinux-config-enforcing

# Install and configure RKHunter for rootkit detection
sudo apt-get install -y rkhunter
sudo rkhunter --update
sudo rkhunter --propupd
sudo rkhunter --checkall --skip-keypress

# Install and configure CHKRootkit for additional rootkit detection
sudo apt-get install -y chkrootkit
sudo chkrootkit

# Install and configure ClamAV for malware detection
sudo apt-get install -y clamav clamav-daemon
sudo freshclam
sudo systemctl enable clamav-daemon
sudo systemctl start clamav-daemon

# Enable AuditD for comprehensive auditing of security events
sudo systemctl enable auditd
sudo systemctl start auditd

########################
# SSH Hardening
########################

# Secure SSH configuration
sudo sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sudo sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config
sudo sed -i 's/#AllowTcpForwarding yes/AllowTcpForwarding no/' /etc/ssh/sshd_config
sudo sed -i 's/#X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
sudo sed -i 's/#UsePAM yes/UsePAM yes/' /etc/ssh/sshd_config
sudo systemctl restart ssh

# Install and configure OpenSCAP for security auditing and compliance checks
sudo apt-get install -y libopenscap8 openscap-scanner
sudo oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_pci-dss /usr/share/xml/scap/ssg/content/ssg-debian8-ds.xml

########################
# Finalizing Security
########################

# Remove unwanted software (like telnet, rsh)
sudo apt-get purge -y telnet rsh-server talk

# Disable unnecessary services
for SERVICE in cups nfs-common rpcbind avahi-daemon bluetooth; do
    sudo systemctl disable $SERVICE
    sudo systemctl stop $SERVICE
done

# Regularly update the system and clean up
sudo apt-get autoremove -y
sudo apt-get update && sudo apt-get upgrade -y

echo "Ultimate hardening complete! Please review and validate settings for your specific needs."
