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
 * replay protection
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

3) Generate a client private key:  tr </dev/urandom -dc 0-9a-f | head -c 64; echo

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

An adversary with packet read capability is also able to copy the
knock packet and send it from their own IP address, racing the
original packet. Therefore please do not use the client IP of the
knock for anything more sensitive than exposing the port to that IP.

Countermeasures:
 * The packet must be signed by a key belonging to the client
 * Each packet can only be used for one port knock on a daemon (due to counter increment)
 * Each knock limits its scope to the IP of the server
 * Each knock limits its scope to the key of the server
 * Each knock only allows for one connect attempt

Further defenses:
 * Packet content is encrypted and length randomized so a very casual
   observer won't recognize the protocol/software being used.
 * Don't publicise the listen port, and set other UDP ports to DROP by default
 * Clients should use a different key for each knock server instance

## Other uses

Gnocchi can be used to perform a range of tasks securely in a single packet, such as:
 * Reboot a server
 * Setting an MoTD on a webpage
 * Sending a small email

## Protocol:


```
SIG = sign(NONCE(24) || MAGIC(8) || SIGNPUB(32) || COUNTER(14) || DATA_LEN(2) || DATA_PLUS_PADDING(0-864) || SERVER_KEY(32) || SERVER_IPV4(4))
PACKET = NONCE(24) || MAC(16) || ciphertext{MAGIC(8) || SIGNPUB(32) || SIG(64) || COUNTER(14) || DATA_LEN(2) || DATA_PLUS_PADDING(0-864)}
```

* NONCE is a fresh random string
* MAC is the ciphertext MAC from crypto_secretbox
* ciphertext is encrypted using the NONCE and server's secret key
* MAGIC is the binary value of "42f9708e2f1369d9"
* SIGNPUB is the client's signing public key
* SIG is the client's signature of the packet data
* COUNTER is the incrementing counter to prevent replay. The counter is incremented by 1 on the client, and succeeds at the server if it is greater than all previously seen counter values.
* SERVER_IPV4 is the server's IP address
* SERVER_KEY is the server's secret key
* DATA_LEN is the amount of DATA that is valid (after that is padding).
* DATA_PLUS_PADDING is DATA_LEN bytes of data, followed by padding to
  be ignored. The padding usually rounds the payload length up to the nearest 16 bytes.

For now data is not supported and DATA_LEN must be zero. Once
implemented, the configuration must define whether data is expected or
not. The server can either accept the client_ip, or accept data.

The reason both are not allowed at the same time is because an
adversary can resend a packet from any IP address, which could have
dangerous implications if the data is trusted to be from the reported
IP address.
