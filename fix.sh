#!/bin/bash

# Advanced Security and Network Hardening Script for Kali Linux by Taylor Newsome
# Including kernel, network, access, monitoring, and advanced intrusion detection

# Harden Command - Usage: harden [options]
# Options:
#   -h, --help      Show help options
#   -k, --kernel    Apply kernel-level hardening
#   -n, --network   Apply network-level hardening
#   -a, --access    Apply user & access control hardening
#   -m, --monitor   Apply monitoring & intrusion detection
#   -s, --ssh       Apply SSH hardening
#   -f, --final     Finalize hardening (disable services, cleanup)

# Function to show help message
show_help() {
    echo "Usage: harden [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help      Show this help message"
    echo "  -k, --kernel    Apply kernel-level hardening"
    echo "  -n, --network   Apply network-level hardening"
    echo "  -a, --access    Apply user & access control hardening"
    echo "  -m, --monitor   Apply monitoring & intrusion detection"
    echo "  -s, --ssh       Apply SSH hardening"
    echo "  -f, --final     Finalize hardening (disable services, cleanup)"
}

# Function for kernel-level hardening
harden_kernel() {
    echo "Applying kernel-level hardening..."
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

    # Disable unprivileged eBPF and user namespaces
    sudo sysctl -w kernel.unprivileged_bpf_disabled=1
    sudo sysctl -w kernel.unprivileged_userns_clone=0

    # Prevent kernel module loading
    echo "kernel.modules_disabled = 1" | sudo tee -a /etc/sysctl.conf
    sudo sysctl -p
}

########################
# GRUB Hardening
# Protect Boot Loader
########################

# Function for GRUB hardening
harden_grub() {
    echo "Protecting GRUB Boot Loader..."
    # Password-protect GRUB (important for full security control)
    sudo apt-get install -y grub-pc
    echo "set superusers=\"root\"" | sudo tee -a /etc/grub.d/40_custom
    echo "password_pbkdf2 root $(grub-mkpasswd-pbkdf2)" | sudo tee -a /etc/grub.d/40_custom
    sudo update-grub
}

########################
# User & Access Control
########################

# Function for user & access control hardening
harden_access() {
    echo "Applying user & access control hardening..."
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
}

########################
# Network Hardening
########################

# Function for network hardening
harden_network() {
    echo "Applying network hardening..."
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
}

########################
# Monitoring & Intrusion Detection
########################

# Function for monitoring & intrusion detection
harden_monitoring() {
    echo "Applying monitoring & intrusion detection..."
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
    sudo systemctl enable rkhunter
    sudo systemctl start rkhunter

    # Install and configure Lynis for security auditing
    sudo apt-get install -y lynis
    sudo lynis audit system

    # Install and configure Logwatch for log monitoring
    sudo apt-get install -y logwatch
    sudo cp /usr/share/logwatch/default.conf/logwatch.conf /etc/logwatch/conf/logwatch.conf

    # Configure Logwatch for daily reports
    echo "MailTo = root" | sudo tee -a /etc/logwatch/conf/logwatch.conf
    echo "Detail = 10" | sudo tee -a /etc/logwatch/conf/logwatch.conf

    # Clean up log files regularly
    echo "0 0 * * * root find /var/log -type f -exec truncate -s 0 {} \;" | sudo tee -a /etc/crontab
}

########################
# SSH Hardening
########################

# Function for SSH hardening
harden_ssh() {
    echo "Applying SSH hardening..."
    # Secure SSH configuration
    sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sudo sed -i 's/#ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
    sudo sed -i 's/#X11Forwarding no/X11Forwarding no/' /etc/ssh/sshd_config
    sudo sed -i 's/#UsePAM yes/UsePAM no/' /etc/ssh/sshd_config
    sudo systemctl restart sshd
}

########################
# Finalization Steps
########################

# Function for finalization steps
finalize_hardening() {
    echo "Finalizing hardening..."
    # Disable unnecessary services
    for SERVICE in telnetd rshd; do
        sudo systemctl stop $SERVICE
        sudo systemctl disable $SERVICE
    done

    # Clean up unused packages
    sudo apt-get autoremove -y

    # Perform a final system update
    sudo apt-get update && sudo apt-get upgrade -y

    # Notify user of completion
    echo "Hardening complete!"
}

# Main script execution
case "$1" in
    -h|--help)
        show_help
        ;;
    -k|--kernel)
        harden_kernel
        harden_grub
        ;;
    -n|--network)
        harden_network
        ;;
    -a|--access)
        harden_access
        ;;
    -m|--monitor)
        harden_monitoring
        ;;
    -s|--ssh)
        harden_ssh
        ;;
    -f|--final)
        finalize_hardening
        ;;
    *)
        echo "Invalid option. Use -h for help."
        ;;
esac
