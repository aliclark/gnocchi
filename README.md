# gnocchi

A secure, auditable port knock daemon.

## Why port knocking

Port knocking is used to restrict access to a non-public network
service (eg. ssh) in cases where the client's IP address is not known
ahead of time (eg. with dynamic residential IP address).

This protects the service against remote attackers with an
unprivileged position on the network - random other hosts on the
internet.

## Why Gnocchi

 * gnocchi is written in Python, with reduced attack surface compared to C
 * gnocchi is around 200 lines, so can be reasonably audited before use
 * replay protection by default
 * can and should be run as non-root user
 * strong cryptographic security
 * fault tolerant
 * stealthy - no feedback in response to network probes

## WARNING

Setting up a port knock firewall is extremely risky and can lead to
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

## Adversary model

The adversary can:
 * Convince the client to send to the adversary's server with the victim server's pubkey
 * Convince the client to send to the adversary's server with the adversary server's pubkey
 * Send packets (eg. UDP, TCP) from their own IP address to the server

Gnocchi does not defend against an adversary who can read packets on
the network, since this capability almost always comes with the
ability to inject arbitrary packets. Such an adversary is capable of
hijacking or spoofing any TCP session from the client, and no port
knocking daemon can protect against this.

Countermeasures:
 * The packet must be signed by a key belonging to the client
 * Each packet can only be used for one port knock on a daemon (due to counter increment)
 * Each knock limits its scope to the IP pairs of the communication
 * Each knock limits its scope to the public key of the daemon
 * Each knock only allows for one connect attempt

Defense in depth (implemented):
 * Packet content is encrypted and length randomized so a casual observer will
   not recognize the protocol/software being used

Defense in depth (you):
 * Don't publish the listen port, and set other UDP ports to DROP by default
 * Don't publish the server's public key
 * Clients should use a different key for each knock server instance

## Protocol:

crypto_box_seal(crypto_box_sign("v02 knock $SERVER_IP $SERVER_PUBKEY $COUNTER_HEX", client_signkey), server_pubkey)

 * SERVER_IP is the ascii IP4 the client expects to connect to, left
   padded to length 15 using spaces.
 * SERVER_PUBKEY is the 64 character hex of the server daemon's encryption key
 * COUNTER_HEX is the counter value in hex, zero padded to length
   32. The counter is incremented by 1 on the client, and succeeds at
   the server if it is greater than all previously seen counter
   values.
