#!/bin/bash

#Allow youself Ping other hosts , prohibit others Ping you
iptables -A INPUT -p icmp --icmp-type 8 -s 0/0 -j DROP
iptables -A OUTPUT -p icmp --icmp-type 8 -s 0/0 -j ACCEPT


#Close all INPUT FORWARD OUTPUT, just open some ports
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

#Open ssh
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT

#Open port 80
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 80 -j ACCEPT


#Open multiport
#iptables -A INPUT -p tcp -m multiport --dport 22,80,8080,8081 -j ACCEPT


#Control IP connection
#The maximum number of connections for a single IP is 30
iptables -I INPUT -p tcp --dport 80 -m connlimit --connlimit-above 30 -j REJECT

#A single IP allows up to 15 new connections in 60 seconds
iptables -A INPUT -p tcp --dport 80 -m recent --name BAD_HTTP_ACCESS --update --seconds 60 --hitcount 15 -j REJECT
iptables -A INPUT -p tcp --dport 80 -m recent --name BAD_HTTP_ACCESS --set -j ACCEPT


#Prevent port reuse
iptables -A OUTPUT -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT


#Filter abnormal packets
iptables -A INPUT -i eth1 -p tcp --tcp-flags SYN,RST,ACK,FIN SYN -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP 
iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL SYN,FIN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL SYN,FIN,PSH -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL SYN,FIN,RST,PSH -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP 
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

#Prevent DoS attacks
iptables -A INPUT -p tcp --dport 80 -m limit --limit 20/minute --limit-burst 100 -j ACCEPT

#Discard unfamiliar TCP response packs to prevent rebound attacks
iptables -A INPUT -m state --state NEW -p tcp ! --syn -j DROP
iptables -A FORWARD -m state --state NEW -p tcp --syn -j DROP