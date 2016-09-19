#!/bin/bash

# Make this file owned by root but readable to a "gnocchi" group, and setuid
# executable like so:
#
# -rwsr-s--- 1 root gnocchi /usr/local/bin/gnocched.sh

ip=$1

if ! [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo Invalid IP address >&2
  exit 1
fi

rule="INPUT -p tcp -s $ip --dport 22 --syn -m state --state NEW -m limit --limit 1/hour --limit-burst 1 -j ACCEPT"

iptables -I $rule
sleep 10
# Could require bash and put this in a trap at exit
iptables -D $rule
