#!/bin/sh

rule="INPUT -p tcp -s $1 --dport 22 --syn -m state --state NEW -m limit --limit 1/hour --limit-burst 1 -j ACCEPT"
iptables -I $rule
sleep 10
iptables -D $rule
