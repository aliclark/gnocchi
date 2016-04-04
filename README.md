# gnocchi

A secure, auditable port knock daemon.


/ WARNING |
Setting up a port knock firewal is extremely risky and can lead to
locking out of a server. Please do not save any firewall to a
persistent state until you are absolutely sure it works. Until that
point, be sure that a hard reboot can get back to a working state.
| WARNING \


I'm not using this software yet. Use at your own risk.


General process:

1) Configure the machine to start the port knock instance on boot with
the valid config file. DO *NOT* PROCEED UNTIL THIS IS CONFIRMED
WORKING.

2) Generate a server key:  tr </dev/urandom -dc 0-9a-f | head -c 64; echo

3) Generate a client key:  tr </dev/urandom -dc 0-9a-f | head -c 64; echo

4.1) Put the keys in the relevant config files.

4.2) Run both client and server to learn the public keys it logs of each, and
put those in each others' configs. NB. the port number used will be based on
the server's public key. If you don't like the port, generate a new server key.


5) set all other UDP ports to DROP by default (instead of sending ICMP
port unreachable).
6) work out which ports are normally accessible (including the port
being configured for port knocking). set iptables to allow NEW
connections to these ports and block others by default, but always
allow ESTABLISHED connections.

6) create a setuid program that allows the source to establish NEW
connections, sleeps for 5 seconds, then removes the rule.

7) Test the above on a test service that is not normally accessible.
8) Test the above on the service being moved behind port knock.

9) BACKUP THE CLIENT CONFIGURATION

10) Remove the rule allowing the service in the firewall by default
(but do not persist it yet). If this fails, a hard reboot should fix.

11) If it works, consider persistently removing the rule that allows
the service from the normal firewall.



Protocol:
crypto_box_seal(crypto_box_sign("v01 knock $CLIENT_IP $SERVER_IP $COUNTER_HEX", client_signkey), server_pubkey)

CLIENT_IP is the ascii IP4 the client expects to be connecting from
SERVER_IP is the ascii IP4 the client expects to connect to
Both IP values are left padded to length 15 using spaces.
COUNTER_HEX is the counter number in hex, zero padded to length 32.


The adversary can:
 * Convince the client to send to their own server with the victim's pubkey
 * Convince the client to send to their own server their own pubkey
 * Read the packet and source, destination details
 * Intercept a client's knock and send it as their own

Countermeasures:
 * The packet must be signed by a key belonging to the client
 * Each packet can only be used for one knock on a daemon (due to counter increment)
 * Each knock limits its scope to the IP pairs of the communication
 * Each knock limits its scope to the public key of the daemon

Defense in depth (implemented):
 * Packet content is encrypted and length randomized to make the
   protocol unclear to most observers

Defense in depth (you):
 * Don't publish the listen port, and set other UDP ports to DROP by default
 * Don't publish the server's public key
 * Clients should use a different key for each knock server instance
