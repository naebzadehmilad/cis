import configparser
import subprocess
import datetime
import logging
conf=configparser.ConfigParser()
conf.add_section('CIS')
conf.set("CIS", "command", "lsmod | grep cramfs,lsmod | grep freevxfs,lsmod | grep jffs2,lsmod | grep hfs,lsmod | grep hfsplus,lsmod | grep squashfs,lsmod | grep udf,lsmod | grep vfat,mount | grep /tmp"
        ",mount | grep /var/tmp, mount | grep /dev/shm,"
         ',systemctl is-enabled autofs,grep ^gpgcheck /etc/yum.conf,rpm -q aide,stat /boot/grub2/grub.cfg,stat /boot/grub2/user.cfg'
',check grep /sbin/sulogin /usr/lib/systemd/system/rescue.service,grep /sbin/sulogin /usr/lib/systemd/system/emergency.service,grep "hard core" /etc/security/limits.conf /etc/security/limits.d/*'
',dmesg | grep NX,sysctl kernel.randomize_va_space,rpm -q prelink,rpm -q setroubleshoot,rpm -q mcstrans,rpm -q libselinux,egrep ''(\\v|\\r|\\m|\\s)'' /etc/issue'
',systemctl -a | grep chargen -dgram,systemctl -a | greo chargen-stream,systemctl -a | grep daytime-dgram,systemctl -a | grep daytime-stream,systemctl -a | grep echo-dgram'
',chown root:root /etc/issue,yum check-update --security,systemctl -a | grep echo-stream,systemctl is-enabled xinetd,rpm -qa xorg-x11*,systemctl is-enabled avahi-daemon'
',systemctl is-enabled cups,systemctl is-enabled dhcpd,systemctl is-enabled nfs,systemctl is-enabled nfs-server,systemctl is-enabled rpcbind,systemctl is-enabled named'
',systemctl is-enabled vsftpd,systemctl is-enabled httpd,systemctl is-enabled dovecot,systemctl is-enabled smb,systemctl is-enabled squid,systemctl is-enabled snmpd'
',netstat -an | grep LIST | grep :25,systemctl is-enabled ypserv,systemctl is-enabled rlogin.socket,systemctl is-enabled rsh.socket,systemctl is-enabled rexec.socket'
',systemctl is-enabled telnet.socket,systemctl is-enabled tftp.socket,systemctl is-enabled rsyncd,systemctl is-enabled ntalk,rpm -q ypbind,rpm -q rsh,rpm -q talk,rpm -q telnet'
',rpm -q openldap-clients,sysctl net.ipv4.ip_forward,sysctl net.ipv4.conf.all.send_redirects,sysctl net.ipv4.conf.default.send_redirects,sysctl net.ipv4.conf.all.accept_source_route'
',sysctl net.ipv4.conf.default.accept_source_route,sysctl net.ipv4.conf.all.accept_redirects,sysctl net.ipv4.conf.default.accept_redirects,sysctl net.ipv4.conf.default.secure_redirects'
',sysctl net.ipv4.conf.all.secure_redirects,sysctl net.ipv4.conf.all.log_martians,sysctl net.ipv4.conf.default.log_martians,sysctl net.ipv4.icmp_echo_ignore_broadcasts'
',sysctl net.ipv4.icmp_ignore_bogus_error_responses,sysctl net.ipv4.conf.all.rp_filter,sysctl net.ipv4.conf.default.rp_filter'
',sysctl net.ipv4.tcp_syncookies,sysctl net.ipv6.conf.all.accept_ra,sysctl net.ipv6.conf.default.accept_ra'
',sysctl net.ipv6.conf.all.accept_redirects,sysctl net.ipv6.conf.default.accept_redirects,grep ^\s*linux /boot/grub2/grub.cfg'
',rpm -q tcp_wrappers,rpm -q tcp_wrappers-libs,lsmod | grep dccp,lsmod | grep sctp,lsmod | grep rds,lsmod | grep tipc'
',grep max_log_file /etc/audit/auditd.conf,grep space_left_action /etc/audit/auditd.conf,grep action_mail_acct /etc/audit/auditd.conf'
',grep max_log_file_action /etc/audit/auditd.conf,systemctl is-enabled auditd,auditctl -l | grep time-change,auditctl -l | grep identity'
',auditctl -l | grep system-locale,grep logins /etc/audit/audit.rules,grep session /etc/audit/audit.rules,auditctl -l | grep perm_mod'
',auditctl -l | grep perm_mod,auditctl -l | grep access,auditctl -l | grep mounts,auditctl -l | grep delete,auditctl -l | grep scope'
',auditctl -l | grep actions,auditctl -l | grep modules,systemctl is-enabled syslog-ng,systemctl is-enabled crond,stat /etc/crontab'
',stat /etc/cron.weekly,stat /etc/cron.monthly,stat /etc/cron.d,stat /etc/ssh/sshd_config,grep ^Protocol /etc/ssh/sshd_config'
',grep ^LogLevel /etc/ssh/sshd_config,grep ^X11Forwarding /etc/ssh/sshd_config,grep ^MaxAuthTries /etc/ssh/sshd_config'
',grep ^IgnoreRhosts /etc/ssh/sshd_config,grep ^HostbasedAuthentication /etc/ssh/sshd_config,grep ^PermitRootLogin /etc/ssh/sshd_config'
',grep ^PermitEmptyPasswords /etc/ssh/sshd_config,grep PermitUserEnvironment /etc/ssh/sshd_config,grep MACs /etc/ssh/sshd_config'
',grep ^ClientAliveInterval /etc/ssh/sshd_config,grep ^ClientAliveCountMax /etc/ssh/sshd_config,grep ^AllowUsers /etc/ssh/sshd_config'
',grep ^Banner /etc/ssh/sshd_config,grep pam_pwquality.so /etc/pam.d/password-auth,grep ^minlen /etc/security/pwquality.conf'
',grep ^dcredit /etc/security/pwquality.conf,grep ^ocredit /etc/security/pwquality.conf,grep ^ucredit /etc/security/pwquality.conf'
',grep ^LoginGraceTime /etc/ssh/sshd_config,grep ^root: /etc/passwd | cut -f4 -d,grep ^TMOUT /etc/bashrc,grep ^TMOUT /etc/profile'
',grep pam_wheel.so /etc/pam.d/su,grep wheel /etc/group,rpm -qf /bin/bash,stat /etc/passwd,stat /etc/shadow,stat /etc/group,stat /etc/gshadow'
',stat /etc/shadow-,stat /etc/group-,grep ^\+: /etc/passwd'

)

conf.add_section('CISEXECUTE')
conf.set("CISEXECUTE", "execute",'rmmod cramfs,rmmod freevxfs,rmmod jffs2,rmmod hfs,rmmod hfsplus,rmmod squashfs,rmmod udf,rmmod vfat'
',systemctl disable autofs,yum install aide -y,aide --init,chmod og-rwx /boot/grub2/grub.cfg,chown root:root /boot/grub2/user.cfg,chmod og-rwx /boot/grub2/user.cfg'
',sysctl -w fs.suid_dumpable=0,chown root:root /boot/grub2/grub.cfg,sysctl -w kernel.randomize_va_space=2,yum install libselinux -y,yum update --security -y'
',sysctl -w net.ipv4.ip_forward=0,sysctl -w net.ipv4.route.flush=1,sysctl -w net.ipv4.conf.all.send_redirects=0,sysctl -w net.ipv4.conf.default.send_redirects=0,sysctl -w net.ipv4.route.flush=1'
',sysctl -w net.ipv4.conf.all.accept_source_route=0,sysctl -w net.ipv4.conf.default.accept_source_route=0,sysctl -w net.ipv4.route.flush=1,sysctl -w net.ipv4.conf.all.accept_redirects=0'
',sysctl -w net.ipv4.conf.default.accept_redirects=0,sysctl -w net.ipv4.route.flush=1,sysctl -w net.ipv4.conf.all.secure_redirects=0,sysctl -w net.ipv4.conf.default.secure_redirects=0'
',sysctl -w net.ipv4.route.flush=1,sysctl -w net.ipv4.conf.all.log_martians=1,sysctl -w net.ipv4.conf.default.log_martians=1,sysctl -w net.ipv4.route.flush=1,sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1'
',sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1,sysctl -w net.ipv4.conf.all.rp_filter=1,sysctl -w net.ipv4.conf.default.rp_filter=1,sysctl -w net.ipv4.tcp_syncookies=1'
',sysctl -w net.ipv6.conf.all.accept_ra=0,sysctl -w net.ipv6.conf.default.accept_ra=0,sysctl -w net.ipv6.route.flush=1,sysctl -w net.ipv6.conf.all.accept_redirects=0'
',sysctl -w net.ipv6.conf.default.accept_redirects=0,sysctl -w net.ipv6.route.flush=1,yum install tcp_wrappers -y,chown root:root /etc/cron.hourly,chmod og-rwx /etc/cron.hourly'
',chown root:root /etc/cron.daily,find /var/log -type f -exec chmod g-wx,o-rwx {} +,chown root:root /etc/ssh/sshd_config,chmod og-rwx /etc/ssh/sshd_config'
         )

with open('conf.cfg', 'w') as configfile:
    conf.write(configfile)
def CIS_CHECK():
    conf.read
    read = conf.get('CIS', 'command').split(',')

    for i in range (len(read)):
        try:
            logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s', datefmt='%H:%M:%S',filename="check.log")
            subprocess.run(f'{read[i]}',check=True,shell=True)

            logging.info(f'execute {read[i]}')
        except:
            logging.warning(f'Fault execute {read[i]}')
def CIS_EXECUTE():
    conf.read
    read = conf.get('CISEXECUTE', 'execute').split(',')

    for i in range (len(read)):
        try:
            logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s', datefmt='%H:%M:%S')
            subprocess.run(f'{read[i]}',check=True,shell=True)
            logging.info(f'execute {read[i]}')
        except:
            logging.warning(f'Fault execute {read[i]}')
CIS_CHECK()
#CIS_EXECUTE()
