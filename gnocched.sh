#!/bin/sh

# something like this

rule="-p tcp -s $1 --dport 22 -j ACCEPT"
iptables -I $rule
sleep 5
iptables -D $rule
