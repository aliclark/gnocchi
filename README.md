# gnocchi

A secure, auditable port knock daemon.

## Why

 * gnocchi is written in Python, with reduced attack surface compared to C
 * gnocchi is around 200 lines, so can be reasonably audited before use
 * replay protection by default
 * can and should be run as non-root user

## WARNING

Setting up a port knock firewal is extremely risky and can lead to
locking out of a server. Please do not save any firewall to a
persistent state until you are absolutely sure it works. Until that
point, be sure that a hard reboot can get back to a working state.

I'm not using this software yet. Use at your own risk.

## General process

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

7) create a setuid program that allows the source to establish NEW
connections, sleeps for 5 seconds, then removes the rule.

8) Test the above on a test service that is not normally accessible.

9) Test the above on the service being moved behind port knock.

10) BACKUP THE CLIENT CONFIGURATION

11) Remove the rule allowing the service in the firewall by default
(but do not persist it yet). If this fails, a hard reboot should fix.

12) If it works, consider persistently removing the rule that allows
the service from the normal firewall.

The adversary can:
 * Convince the client to send to the adversary's server with the victim server's pubkey
 * Convince the client to send to the adversary's server with the adversary server's pubkey
 * Read any packets on the network
 * OR
 * Drop or inject any packets on the network

Gnocchi does not defend against an adversary who can both read and
arbitrarily inject on the network.

Such an adversary could allow the knock to go ahead and quickly
connect to the now opened service with injected syn TCP packet and
reading the TCP syn/ack of the server.

No port knocking systems can defend against this attack, however
Gnocchi only allows a single syn packet through, so the valid user
will have some feedback when their own session fails to connect
(bearing in mind that normal packet loss can have the same effect).

Countermeasures:
 * The packet must be signed by a key belonging to the client
 * Each packet can only be used for one knock on a daemon (due to counter increment)
 * Each knock limits its scope to the IP pairs of the communication
 * Each knock limits its scope to the public key of the daemon

Defense in depth (implemented):
 * Packet content is encrypted and length randomized so a casual observer will
   not recognize the protocol/software being used

Defense in depth (you):
 * Don't publish the listen port, and set other UDP ports to DROP by default
 * Don't publish the server's public key
 * Clients should use a different key for each knock server instance

### Protocol:

crypto_box_seal(crypto_box_sign("v01 knock $CLIENT_IP $SERVER_IP $COUNTER_HEX", client_signkey), server_pubkey)

 * CLIENT_IP is the ascii IP4 the client expects to be connecting from
 * SERVER_IP is the ascii IP4 the client expects to connect to
 * Both IP values are left padded to length 15 using spaces.
 * COUNTER_HEX is the counter number in hex, zero padded to length 32.

