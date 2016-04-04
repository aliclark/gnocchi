#!/usr/bin/env python2

import os
import sys
import re
import time
import random
import pysodium
import socket

server_public_key = None
server_ip = None
server_port = None

client_sign_private_key = None
client_sign_public_key = None

state_file = None

server_public_key_regex = re.compile(r'^([0-9a-f]{'+str(pysodium.crypto_box_PUBLICKEYBYTES*2)+r'})$')
client_seed_regex = re.compile(r'^([0-9a-f]{64})$')

def log(msg):
    sys.stderr.write(time.strftime('%Y-%m-%d %H:%M:%S')+' '+msg+'\n')

def parse_server_public_key(keystr):
    m = server_public_key_regex.match(keystr)
    if not m:
        return None
    return m.group(1).decode('hex')

def port_from_pubkey(pk):
    return (ord(pk[-2]) << 8) | ord(pk[-1])

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

    elif parts[0] == 'server_public_key':
        if len(parts) != 2:
            continue
        server_public_key = parse_server_public_key(parts[1])
        server_port = port_from_pubkey(server_public_key)

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


# FIXME: file should be locked over this
counter = read_counter()
write_counter(counter + 1)
# FIXME: unlock file

log('[INFO] knock '+server_ip+':'+str(server_port)+' '+server_public_key.encode('hex')+' '+client_sign_public_key.encode('hex'))

command = 'v02 knock '+server_ip.rjust(15)+' '+server_public_key.encode('hex')+' '+hex(counter)[2:].zfill(32)+(' '*5)
assert len(command) == 128
pad_blocks = random.randint(0, 49)
command += ' ' * (pad_blocks * 16)

signed = pysodium.crypto_sign(command, client_sign_private_key)
cdata = pysodium.crypto_box_seal(signed, server_public_key)
assert len(cdata) <= 1024

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(cdata, (server_ip, server_port))
