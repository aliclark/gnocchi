#!/usr/bin/env python2

import os
import sys
import re
import socket
import pysodium
import time
import subprocess
import random

state_file = None
server_private_key = None
server_ip = None
server_port = None

# server only
client_sign_keys = []
knocked_command = None

# client only
client_sign_private_key = None
client_sign_public_key = None

is_client = False

server_private_key_regex = re.compile(r'^([0-9a-f]{64})$')

client_key_regex = re.compile(r'^([0-9a-f]{'+str(pysodium.crypto_sign_PUBLICKEYBYTES*2)+r'})$')
client_seed_regex = re.compile(r'^([0-9a-f]{64})$')


def log(msg, client_ip=None, client_port=None, post=''):
    sys.stderr.write(time.strftime('%Y-%m-%d %H:%M:%S')+' '+msg+(' from '+client_ip+':'+str(client_port) if client_ip and client_port else '')+(': '+repr(post) if post else '')+'\n')


def parse_client_sign_key(keystr):
    m = client_key_regex.match(keystr)
    if not m:
        return None
    return m.group(1).decode('hex')

def port_from_private_key(k):
    h = pysodium.crypto_generichash(k)
    return (ord(h[-2]) << 8) | ord(h[-1])

def port_from_pubkey(pk):
    return (ord(pk[-2]) << 8) | ord(pk[-1])

def parse_server_private_key(keystr):
    m = server_private_key_regex.match(keystr)
    if not m:
        return None
    return m.group(1).decode('hex')

def parse_client_keypair(keystr):
    m = client_seed_regex.match(keystr)
    if not m:
        return None
    return pysodium.crypto_sign_seed_keypair(m.group(1).decode('hex'))

# FIXME: file should be locked over this
# FIXME: read on per-client basis
def read_counter():
    # allow the file to auto-create
    if not os.path.exists(state_file):
        log('[WARN] state file does not exist yet, using counter 0')
        return 1 if is_client else 0
    with open(state_file, 'r') as statefile:
        statelines = statefile.read().splitlines()

    counter = None

    for l in statelines:
        parts = l.split(' ')
        parts = [part.strip() for part in parts if part]
        if not parts:
            continue
        if parts[0] == 'client':
            if len(parts) != 3:
                continue

            # TODO: multiclient

            counter = int(parts[2])

    return counter

# FIXME: file should be locked over this
# FIXME: write on per-client basis
def write_counter(c):
    if not os.path.exists(state_file):
        log('[WARN] state file does not exist yet, writing counter '+str(c))
    with open(state_file, 'w') as statefile:
        statefile.write('client RESERVED '+str(c)+'\n')

def saferandom(n):
    if not n:
        return b''
    # hash so we don't print prng output onto the network
    return pysodium.crypto_generichash(pysodium.randombytes(min(n, 32)), outlen=n)

def roundup(n, m):
    return n if (n % m) == 0 else (n + m) - (n % m)

def run_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((server_ip, server_port))

    log('[INFO] Listening on '+server_ip+':'+str(server_port))

    # NONCE(24) + MAC(16) + MAGIC(8) + SIGNPUB(32) + SIG(64) + COUNTER(14) + LEN(2) + REST

    PROTO_MIN_SIZE = 160

    magic_bin = '42f9708e2f1369d9'.decode('hex') # chosen by fair die
    server_ip_bin = socket.inet_aton(server_ip)

    # FIXME: lock state file for duration of the program
    counter = read_counter()

    while True:
        try:
            client_ip, client_port = (None, None)
            cdata, (client_ip, client_port) = sock.recvfrom(1024)

            if len(cdata) < PROTO_MIN_SIZE:
                # normal: a UDP scan would cause this
                log('[INFO] small packet', client_ip, client_port)
                continue

            pkt_nonce = cdata[:pysodium.crypto_secretbox_NONCEBYTES]

            try:
                plain = pysodium.crypto_secretbox_open(cdata[pysodium.crypto_secretbox_NONCEBYTES:],
                                                       pkt_nonce,
                                                       server_private_key)
            except:
                # normal-ish: any big enough packet to the port will cause
                # this, but unless knockd happens to run on a common UDP
                # port there's not much reason to see such a big packet
                log('[INFO] incorrect ciphertext', client_ip, client_port)
                continue

            pkt_magic = plain[:8]
            plain = plain[8:]

            if pkt_magic != magic_bin:
                # unrecognised protocol version
                log('[WARN] unrecognised version magic', client_ip, client_port, pkt_magic.encode('hex'))
                continue

            pkt_sign_pub = plain[:32]
            plain = plain[32:]

            if pkt_sign_pub not in client_sign_keys:
                log('[WARN] unrecognised client sign key', client_ip, client_port, pkt_sign_pub.encode('hex'))
                continue

            pkt_sig = plain[:64]
            plain = plain[64:]

            pkt_counter_bin = plain[:14]
            pkt_counter = int(pkt_counter_bin.encode('hex'), 16)
            plain = plain[14:]

            # check counter early so we don't need to verify replays
            if pkt_counter <= counter:
                log('[POSSIBLE_REPLAY] bad counter', client_ip, client_port)
                continue

            try:
                pysodium.crypto_sign_verify_detached(pkt_sig,
                                                     (pkt_nonce + magic_bin + pkt_sign_pub +
                                                      pkt_counter_bin + plain +
                                                      server_private_key + server_ip_bin),
                                                     pkt_sign_pub)
            except:
                # shenanigans, the data isn't signed by that user
                log('[SEVERE] bad signature', client_ip, client_port)
                continue

            pkt_data_len_bin = plain[:2]
            pkt_data_len = int(pkt_data_len_bin.encode('hex'), 16)
            plain = plain[2:]

            pkt_data = plain[:pkt_data_len]

            # Cool, write that counter ASAP so the packet can't be used again
            counter = pkt_counter
            write_counter(counter)

            log('[INFO] valid knock', client_ip, client_port)

            # NB. do *not* trust that client_ip is the originator (beyond
            # port knocking functionality). A person who can perform
            # packet captures can race the packet from their own IP
            subprocess.Popen([knocked_command, client_ip, pkt_data])


        except KeyboardInterrupt:
            break

        except Exception as e:
            log('[ERROR] packet exception', client_ip, client_port, e)


def run_client():
    # FIXME: lock state file for duration of the program
    counter = read_counter()
    write_counter(counter + 1)

    log('[INFO] knock '+server_ip+':'+str(server_port)+' '+client_sign_public_key.encode('hex'))

    # NONCE(24) + MAC(16) + MAGIC(8) + SIGNPUB(32) + SIG(64) + COUNTER(14) + LEN(2) + REST

    PROTO_MIN_SIZE = 160

    arg = sys.argv[2] if len(sys.argv) > 2 else b''
    if PROTO_MIN_SIZE + len(arg) > 1024:
        log('[ERROR] argument too long')
        sys.exit(1)

    padded_min_size = PROTO_MIN_SIZE + roundup(len(arg), 16)
    padding = '\x00' * ((roundup(len(arg), 16) - len(arg)) +
                        (16 * random.randint(0, (1024 - padded_min_size) / 16)))

    nonce = saferandom(pysodium.crypto_secretbox_NONCEBYTES)

    magic_bin = '42f9708e2f1369d9'.decode('hex') # chosen by fair die
    counter_bin = hex(counter)[2:].zfill(28).decode('hex')
    data_len_bin = '0000'.decode('hex')
    server_ip_bin = socket.inet_aton(server_ip)

    sig = pysodium.crypto_sign_detached((nonce + magic_bin + client_sign_public_key +
                                         counter_bin + data_len_bin + arg + padding +
                                         server_private_key + server_ip_bin),
                                        client_sign_private_key)

    cdata = nonce + pysodium.crypto_secretbox((magic_bin + client_sign_public_key + sig +
                                               counter_bin + data_len_bin + arg + padding),
                                              nonce,
                                              server_private_key)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(cdata, (server_ip, server_port))
    log('[INFO] sent '+str(len(cdata)))

def main():
    if is_client:
        run_client()
    else:
        run_server()


### TODO: stricter config parsing

cfg = open(sys.argv[1], 'r')
cfglines = cfg.read().splitlines()

for l in cfglines:
    parts = l.split(' ')
    parts = [part.strip() for part in parts if part]

    if not parts:
        continue

    elif parts[0] == 'server_ip':
        if len(parts) != 2:
            continue
        server_ip = parts[1]

    elif parts[0] == 'server_private_key':
        if len(parts) != 2:
            continue
        server_private_key = parse_server_private_key(parts[1])
        server_port = port_from_private_key(server_private_key)
        if server_port <= 1024:
            log('[ERROR] This key maps to a low port. Please generate a new server key')
            sys.exit(1)

    # server only

    elif parts[0] == 'client_public_key':
        if len(parts) != 2:
            continue
        client_sign_keys.append(parse_client_sign_key(parts[1]))

    elif parts[0] == 'server_state':
        if len(parts) != 2:
            continue
        state_file = parts[1]

    elif parts[0] == 'command':
        if len(parts) != 2:
            continue
        knocked_command = parts[1]

    # client only

    elif parts[0] == 'client_private_key':
        if len(parts) != 2:
            continue
        client_sign_public_key, client_sign_private_key = parse_client_keypair(parts[1])
        is_client = True

    elif parts[0] == 'client_state':
        if len(parts) != 2:
            continue
        state_file = parts[1]
        is_client = True

main()
