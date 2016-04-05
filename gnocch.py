#!/usr/bin/env python2

import os
import sys
import re
import time
import random
import pysodium
import socket

server_private_key = None
server_ip = None
server_port = None

client_sign_private_key = None
client_sign_public_key = None

state_file = None

server_private_key_regex = re.compile(r'^([0-9a-f]{64})$')
client_seed_regex = re.compile(r'^([0-9a-f]{64})$')

def log(msg):
    sys.stderr.write(time.strftime('%Y-%m-%d %H:%M:%S')+' '+msg+'\n')

def parse_server_private_key(keystr):
    m = server_private_key_regex.match(keystr)
    if not m:
        return None
    return m.group(1).decode('hex')

def port_from_private_key(k):
    h = pysodium.crypto_generichash(k)
    return (ord(h[-2]) << 8) | ord(h[-1])

def parse_client_keypair(keystr):
    m = client_seed_regex.match(keystr)
    if not m:
        return None
    return pysodium.crypto_sign_seed_keypair(m.group(1).decode('hex'))

cfg = open(sys.argv[1], 'r')
cfglines = cfg.read().splitlines()

for l in cfglines:
    parts = l.split(' ')
    parts = [part.strip() for part in parts if part]

    if not parts:
        continue

    if parts[0] == 'server_ip':
        if len(parts) != 2:
            continue
        server_ip = parts[1]

    elif parts[0] == 'client_private_key':
        if len(parts) != 2:
            continue
        client_sign_public_key, client_sign_private_key = parse_client_keypair(parts[1])

    elif parts[0] == 'server_private_key':
        if len(parts) != 2:
            continue
        server_private_key = parse_server_private_key(parts[1])
        server_port = port_from_private_key(server_private_key)

    elif parts[0] == 'state_file':
        if len(parts) != 2:
            continue
        state_file = parts[1]

# FIXME: read on per-client basis
def read_counter():
    if not os.path.exists(state_file):
        log('[WARN] state file does not exist yet, using counter 1')
        return 1
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
    return pysodium.crypto_generichash(pysodium.randombytes(n), outlen=n)

# FIXME: file should be locked over this
counter = read_counter()
write_counter(counter + 1)
# FIXME: unlock file

log('[INFO] knock '+server_ip+':'+str(server_port)+' '+client_sign_public_key.encode('hex'))

# NONCE(24) + MAC(16) + MAGIC(8) + SIGNPUB(32) + SIG(64) + COUNTER(14) + LEN(2) + REST

nonce = saferandom(pysodium.crypto_secretbox_NONCEBYTES)
pad_blocks = random.randint(0, 54)

magic_bin = '42f9708e2f1369d9'.decode('hex') # chosen by fair die
counter_bin = hex(counter)[2:].zfill(28).decode('hex')
data_len_bin = '0000'.decode('hex')
rest_bin = '\x00' * (pad_blocks * 16)
server_ip_bin = socket.inet_aton(server_ip)

sig = pysodium.crypto_sign_detached((nonce + magic_bin + client_sign_public_key +
                                     counter_bin + data_len_bin + rest_bin +
                                     server_private_key + server_ip_bin),
                                    client_sign_private_key)

cdata = nonce + pysodium.crypto_secretbox((magic_bin + client_sign_public_key + sig +
                                           counter_bin + data_len_bin + rest_bin),
                                          nonce,
                                          server_private_key)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(cdata, (server_ip, server_port))
