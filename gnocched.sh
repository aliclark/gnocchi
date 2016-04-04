#!/bin/sh

# Make this file owned by root but readable to a "gnocchi" group, and setuid
# executable like so:
#
# -rwsr-s--- 1 root gnocchi /usr/local/bin/gnocched.sh

rule="INPUT -p tcp -s $1 --dport 22 --syn -m state --state NEW -m limit --limit 1/hour --limit-burst 1 -j ACCEPT"
iptables -I $rule
sleep 10
# Could require bash and put this in a trap at exit
iptables -D $rule
