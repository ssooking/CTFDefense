#!/bin/bash

echo "         (__)"

echo "         (oo)"

echo "   /------\/ "

echo "  / |    ||  "

echo " *  /\---/\  "

echo "   ~~   ~~   "

echo "...."Are You Ready?"..."

read key

echo "警告：本脚本只是一个检查的操作，未对服务器做任何修改，管理员可以根据此报告进行相应的设置。"

echo ---------------------------------------主机安全检查-----------------------

echo "系统版本"

uname -a

echo --------------------------------------------------------------------------

echo "本机的ip地址是："

ifconfig | grep --color "\([0-9]\{1,3\}\.\)\{3\}[0-9]\{1,3\}"

echo --------------------------------------------------------------------------

awk -F":" '{if($2!~/^!|^*/){print "("$1")" " 是一个未被锁定的账户，请管理员检查是否需要锁定它或者删除它。"}}' /etc/shadow

echo --------------------------------------------------------------------------

more /etc/login.defs | grep -E "PASS_MAX_DAYS" | grep -v "#" |awk -F' '  '{if($2!=90){print "/etc/login.defs里面的"$1 "设置的是"$2"天，请管理员改成90天。"}}'

echo --------------------------------------------------------------------------

more /etc/login.defs | grep -E "PASS_MIN_LEN" | grep -v "#" |awk -F' '  '{if($2!=6){print "/etc/login.defs里面的"$1 "设置的是"$2"个字符，请管理员改成6个字符。"}}'

echo --------------------------------------------------------------------------

more /etc/login.defs | grep -E "PASS_WARN_AGE" | grep -v "#" |awk -F' '  '{if($2!=10){print "/etc/login.defs里面的"$1 "设置的是"$2"天，请管理员将口令到期警告天数改成10天。"}}'

echo --------------------------------------------------------------------------

grep TMOUT /etc/profile /etc/bashrc > /dev/null|| echo "未设置登录超时限制，请设置之，设置方法：在/etc/profile或者/etc/bashrc里面添加TMOUT=600参数"

echo --------------------------------------------------------------------------

if ps -elf |grep xinet |grep -v "grep xinet";then

echo "xinetd 服务正在运行，请检查是否可以把xinnetd服务关闭"

else

echo "xinetd 服务未开启"

fi

echo --------------------------------------------------------------------------

echo "查看系统密码文件修改时间"

ls -ltr /etc/passwd

echo --------------------------------------------------------------------------

echo  "查看是否开启了ssh服务"

if service sshd status | grep -E "listening on|active \(running\)"; then

echo "SSH服务已开启"

else

echo "SSH服务未开启"

fi

echo --------------------------------------------------------------------------

echo "查看是否开启了TELNET服务"

if more /etc/xinetd.d/telnetd 2>&1|grep -E "disable=no"; then

echo  "TELNET服务已开启 "

else

echo  "TELNET服务未开启 "

fi

echo --------------------------------------------------------------------------

echo  "查看系统SSH远程访问设置策略(host.deny拒绝列表)"

if more /etc/hosts.deny | grep -E "sshd: ";more /etc/hosts.deny | grep -E "sshd"; then

echo  "远程访问策略已设置 "

else

echo  "远程访问策略未设置 "

fi

echo --------------------------------------------------------------------------

echo  "查看系统SSH远程访问设置策略(hosts.allow允许列表)"

if more /etc/hosts.allow | grep -E "sshd: ";more /etc/hosts.allow | grep -E "sshd"; then

echo  "远程访问策略已设置 "

else

echo  "远程访问策略未设置 "

fi

echo "当hosts.allow和 host.deny相冲突时，以hosts.allow设置为准。"

echo -------------------------------------------------------------------------

echo "查看shell是否设置超时锁定策略"

if more /etc/profile | grep -E "TIMEOUT= "; then

echo  "系统设置了超时锁定策略 "

else

echo  "未设置超时锁定策略 "

fi

echo -------------------------------------------------------------------------

echo "查看syslog日志审计服务是否开启"

if service syslog status | egrep " active \(running";then

echo "syslog服务已开启"

else

echo "syslog服务未开启，建议通过service syslog start开启日志审计功能"

fi

echo -------------------------------------------------------------------------

echo "查看syslog日志是否开启外发"

if more /etc/rsyslog.conf | egrep "@...\.|@..\.|@.\.|\*.\* @...\.|\*\.\* @..\.|\*\.\* @.\.";then

echo "客户端syslog日志已开启外发"

else

echo "客户端syslog日志未开启外发"

fi

echo -------------------------------------------------------------------------

echo "查看passwd文件中有哪些特权用户"

awk -F: '$3==0 {print $1}' /etc/passwd

echo ------------------------------------------------------------------------

echo "查看系统中是否存在空口令账户"

awk -F: '($2=="!!") {print $1}' /etc/shadow

echo "该结果不适用于Ubuntu系统"

echo ------------------------------------------------------------------------

echo "查看系统中root用户外连情况"

lsof -u root |egrep "ESTABLISHED|SYN_SENT|LISTENING"

echo ----------------------------状态解释------------------------------

echo "ESTABLISHED的意思是建立连接。表示两台机器正在通信。"

echo "LISTENING的"

echo "SYN_SENT状态表示请求连接"

echo ------------------------------------------------------------------------

echo "查看系统中root用户TCP连接情况"

lsof -u root |egrep "TCP"

echo ------------------------------------------------------------------------

echo "查看系统中存在哪些非系统默认用户"

echo "root:x:“该值大于500为新创建用户，小于或等于500为系统初始用户”"

more /etc/passwd |awk -F ":" '{if($3>500){print "/etc/passwd里面的"$1 "的值为"$3"，请管理员确认该账户是否正常。"}}'

echo ------------------------------------------------------------------------

echo "检查系统守护进程"

more /etc/xinetd.d/rsync | grep -v "^#"

echo ------------------------------------------------------------------------

echo "检查系统是否存在入侵行为"

more /var/log/secure |grep refused

echo ------------------------------------------------------------------------

echo "-----------------------检查系统是否存在PHP脚本后门---------------------"

if find / -type f -name *.php | xargs egrep -l "mysql_query\($query, $dbconn\)|专用网马|udf.dll|class PHPzip\{|ZIP压缩程序 荒野无灯修改版|$writabledb|AnonymousUserName|eval\(|Root_CSS\(\)|黑狼PHP木马|eval\(gzuncompress\(base64_decode|if\(empty\($_SESSION|$shellname|$work_dir |PHP木马|Array\("$filename"| eval\($_POST\[|class packdir|disk_total_space|wscript.shell|cmd.exe|shell.application|documents and settings|system32|serv-u|提权|phpspy|后门" |sort -n|uniq -c |sort -rn 1>/dev/null 2>&1;then

echo "检测到PHP脚本后门"

find / -type f -name *.php | xargs egrep -l "mysql_query\($query, $dbconn\)|专用网马|udf.dll|class PHPzip\{|ZIP压缩程序 荒野无灯修改版|$writabledb|AnonymousUserName|eval\(|Root_CSS\(\)|黑狼PHP木马|eval\(gzuncompress\(base64_decode|if\(empty\($_SESSION|$shellname|$work_dir |PHP木马|Array\("$filename"| eval\($_POST\[|class packdir|disk_total_space|wscript.shell|cmd.exe|shell.application|documents and settings|system32|serv-u|提权|phpspy|后门" |sort -n|uniq -c |sort -rn

find / -type f -name *.php | xargs egrep -l "mysql_query\($query, $dbconn\)|专用网马|udf.dll|class PHPzip\{|ZIP压缩程序 荒野无灯修改版|$writabledb|AnonymousUserName|eval\(|Root_CSS\(\)|黑狼PHP木马|eval\(gzuncompress\(base64_decode|if\(empty\($_SESSION|$shellname|$work_dir |PHP木马|Array\("$filename"| eval\($_POST\[|class packdir|disk_total_space|wscript.shell|cmd.exe|shell.application|documents and settings|system32|serv-u|提权|phpspy|后门" |sort -n|uniq -c |sort -rn |awk '{print $2}' | xargs -I{} cp {} /tmp/

echo "后门样本已拷贝到/tmp/目录"

else

echo "未检测到PHP脚本后门"

fi

echo ------------------------------------------------------------------------

echo "-----------------------检查系统是否存在JSP脚本后门---------------------"

find / -type f -name *.jsp | xargs egrep -l "InputStreamReader\(this.is\)|W_SESSION_ATTRIBUTE|strFileManag|getHostAddress|wscript.shell|gethostbyname|cmd.exe|documents and settings|system32|serv-u|提权|jspspy|后门" |sort -n|uniq -c |sort -rn 2>&1

find / -type f -name *.jsp | xargs egrep -l "InputStreamReader\(this.is\)|W_SESSION_ATTRIBUTE|strFileManag|getHostAddress|wscript.shell|gethostbyname|cmd.exe|documents and settings|system32|serv-u|提权|jspspy|后门" |sort -n|uniq -c |sort -rn| awk '{print $2}' | xargs -I{} cp {} /tmp/  2>&1 

echo ------------------------------------------------------------------------

echo "----------------------检查系统是否存在HTML恶意代码---------------------"

if find / -type f -name *.html | xargs egrep -l "WriteData|svchost.exe|DropPath|wsh.Run|WindowBomb|a1.createInstance|CurrentVersion|myEncString|DropFileName|a = prototype;|204.351.440.495.232.315.444.550.64.330" 1>/dev/null 2>&1;then

echo "发现HTML恶意代码"

find / -type f -name *.html | xargs egrep -l "WriteData|svchost.exe|DropPath|wsh.Run|WindowBomb|a1.createInstance|CurrentVersion|myEncString|DropFileName|a = prototype;|204.351.440.495.232.315.444.550.64.330" |sort -n|uniq -c |sort -rn

find / -type f -name *.html | xargs egrep -l "WriteData|svchost.exe|DropPath|wsh.Run|WindowBomb|a1.createInstance|CurrentVersion|myEncString|DropFileName|a = prototype;|204.351.440.495.232.315.444.550.64.330" |sort -n|uniq -c |sort -rn| awk '{print $2}' | xargs -I{} cp {} /tmp/

echo "后门样本已拷贝到/tmp/目录"

else

echo "未检测到HTML恶意代码"

fi

echo "----------------------检查系统是否存在perl恶意程序----------------------"

if find / -type f -name *.pl | xargs egrep -l "SHELLPASSWORD|shcmd|backdoor|setsockopt|IO::Socket::INET;" 1>/dev/null 2>&1;then

echo "发现perl恶意程序"

find / -type f -name *.pl | xargs egrep -l "SHELLPASSWORD|shcmd|backdoor|setsockopt|IO::Socket::INET;"|sort -n|uniq -c |sort -rn

find / -type f -name *.pl | xargs egrep -l "SHELLPASSWORD|shcmd|backdoor|setsockopt|IO::Socket::INET;"|sort -n|uniq -c |sort -rn| awk '{print $2}' | xargs -I{} cp {} /tmp/

echo "可疑样本已拷贝到/tmp/目录"

else

echo "未检测到perl恶意程序"

fi

echo "----------------------检查系统是否存在Python恶意程序----------------------"

find / -type f -name *.py | xargs egrep -l "execCmd|cat /etc/issue|getAppProc|exploitdb" |sort -n|uniq -c |sort -rn

find / -type f -name *.py | xargs egrep -l "execCmd|cat /etc/issue|getAppProc|exploitdb" |sort -n|uniq -c |sort -rn| awk '{print $2}' | xargs -I{} cp {} /tmp/

echo ------------------------------------------------------------------------

echo "-----------------------检查系统是否存在恶意程序---------------------"

find / -type f -perm -111  |xargs egrep "UpdateProcessER12CUpdateGatesE6C|CmdMsg\.cpp|MiniHttpHelper.cpp|y4'r3 1uCky k1d\!|execve@@GLIBC_2.0|initfini.c|ptmalloc_unlock_all2|_IO_wide_data_2|system@@GLIBC_2.0|socket@@GLIBC_2.0|gettimeofday@@GLIBC_2.0|execl@@GLIBC_2.2.5|WwW.SoQoR.NeT|2.6.17-2.6.24.1.c|Local Root Exploit|close@@GLIBC_2.0|syscall\(\__NR\_vmsplice,|Linux vmsplice Local Root Exploit|It looks like the exploit failed|getting root shell" 2>/dev/null

echo ------------------------------------------------------------------------

echo "检查网络连接和监听端口"

netstat -an 

echo "--------------------------路由表、网络连接、接口信息--------------"

netstat -rn 

echo "------------------------查看网卡详细信息--------------------------"

ifconfig -a 

echo ------------------------------------------------------------------------

echo "查看正常情况下登录到本机的所有用户的历史记录"

last

echo ------------------------------------------------------------------------

echo "检查系统中core文件是否开启"

ulimit -c

echo "core是unix系统的内核。当你的程序出现内存越界的时候,操作系统会中止你的进程,并将当前内存状态倒出到core文件中,以便进一步分析，如果返回结果为0，则是关闭了此功能，系统不会生成core文件"

echo ------------------------------------------------------------------------

echo "检查系统中关键文件修改时间"

ls -ltr /bin/ls /bin/login /etc/passwd /bin/ps /usr/bin/top /etc/shadow|awk '{print "文件名："$8"  ""最后修改时间："$6" "$7}'

echo "ls文件：是存储ls命令的功能函数，被删除以后，就无法执行ls命令，黑客可利用篡改ls文件来执行后门或其他程序。

login文件：login是控制用户登录的文件，一旦被篡改或删除，系统将无法切换用户或登陆用户

user/bin/passwd是一个命令，可以为用户添加、更改密码，但是，用户的密码并不保存在/etc/passwd当中，而是保存在了/etc/shadow当中

etc/passwd是一个文件，主要是保存用户信息。

sbin/portmap是文件转换服务，缺少该文件后，无法使用磁盘挂载、转换类型等功能。

bin/ps 进程查看命令功能支持文件，文件损坏或被更改后，无法正常使用ps命令。

usr/bin/top  top命令支持文件，是Linux下常用的性能分析工具,能够实时显示系统中各个进程的资源占用状况。

etc/shadow shadow 是 /etc/passwd 的影子文件，密码存放在该文件当中，并且只有root用户可读。"

echo --------------------------------------------------------------------------

echo "-------------------查看系统日志文件是否存在--------------------"

log=/var/log/syslog

log2=/var/log/messages

if [ -e "$log" ]; then

echo  "syslog日志文件存在！ "

else

echo  "/var/log/syslog日志文件不存在！ "

fi

if [ -e "$log2" ]; then

echo  "/var/log/messages日志文件存在！ "

else

echo  "/var/log/messages日志文件不存在！ "

fi

echo --------------------------------------------------------------------------

echo "检查系统文件完整性2(MD5检查)"

echo "该项会获取部分关键文件的MD5值并入库，默认保存在/etc/md5db中"

echo "如果第一次执行，则会提示md5sum: /sbin/portmap: 没有那个文件或目录"

echo "第二次重复检查时，则会对MD5DB中的MD5值进行匹配，来判断文件是否被更改过"

file="/etc/md5db"

if [ -e "$file" ]; then md5sum -c /etc/md5db 2>&1; 

else 

md5sum /etc/passwd >>/etc/md5db

md5sum /etc/shadow >>/etc/md5db

md5sum /etc/group >>/etc/md5db

md5sum /usr/bin/passwd >>/etc/md5db

md5sum /sbin/portmap>>/etc/md5db

md5sum /bin/login >>/etc/md5db

md5sum /bin/ls >>/etc/md5db

md5sum /bin/ps >>/etc/md5db

md5sum /usr/bin/top >>/etc/md5db;

fi

echo ----------------------------------------------------------------------

echo "------------------------主机性能检查--------------------------------"

echo "CPU检查"

dmesg | grep -i cpu

echo -----------------------------------------------------------------------

more /proc/cpuinfo

echo -----------------------------------------------------------------------

echo "内存状态检查"

vmstat 2 5

echo -----------------------------------------------------------------------

more /proc/meminfo

echo -----------------------------------------------------------------------

free -m

echo -----------------------------------------------------------------------

echo "文件系统使用情况"

df -h

echo -----------------------------------------------------------------------

echo "网卡使用情况"

lspci -tv

echo ----------------------------------------------------------------------

echo "查看僵尸进程"

ps -ef | grep zombie

echo ----------------------------------------------------------------------

echo "耗CPU最多的进程"

ps auxf |sort -nr -k 3 |head -5

echo ----------------------------------------------------------------------

echo "耗内存最多的进程"

ps auxf |sort -nr -k 4 |head -5

echo ----------------------------------------------------------------------

echo ---------------------------------------------------------------------

echo "COPY RIGHT  鬼魅羊羔"

echo "QQ：183126820"

echo ---------------------------------------------------------------------
