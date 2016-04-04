#!/usr/bin/env python2

import os
import sys
import re
import socket
import pysodium
import time
import subprocess

server_public_key = None
server_private_key = None
server_ip = None
server_port = None
client_sign_keys = []
knocked_command = None

client_key_regex = re.compile(r'^([0-9a-f]{'+str(pysodium.crypto_sign_PUBLICKEYBYTES*2)+r'})$')
server_seed_regex = re.compile(r'^([0-9a-f]{64})$')

def log(msg, client_ip=None, client_port=None, post=''):
    sys.stderr.write(time.strftime('%Y-%m-%d %H:%M:%S')+' '+msg+(' from '+client_ip+':'+str(client_port)+(': '+repr(post) if post else '') if client_ip and client_port else '')+'\n')

def parse_client_sign_key(keystr):
    m = client_key_regex.match(keystr)
    if not m:
        return None
    return m.group(1).decode('hex')

def port_from_pubkey(pk):
    return (ord(pk[-2]) << 8) | ord(pk[-1])

def parse_server_keypair(keystr):
    m = server_seed_regex.match(keystr)
    if not m:
        return None
    return pysodium.crypto_box_seed_keypair(m.group(1).decode('hex'))

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

    elif parts[0] == 'command':
        if len(parts) != 2:
            continue
        knocked_command = parts[1]

    elif parts[0] == 'server_private_key':
        if len(parts) != 2:
            continue
        server_public_key, server_private_key = parse_server_keypair(parts[1])
        server_port = port_from_pubkey(server_public_key)
        if server_port <= 1024:
            log('[ERROR] This key maps to a low port. Please generate a new server key')
            sys.exit(1)

    elif parts[0] == 'client_public_key':
        if len(parts) != 2:
            continue
        client_sign_keys.append(parse_client_sign_key(parts[1]))

    elif parts[0] == 'state_file':
        if len(parts) != 2:
            continue
        state_file = parts[1]

# FIXME: file should be locked over this
# FIXME: read on per-client basis
def read_counter():
    # allow the file to auto-create
    if not os.path.exists(state_file):
        log('[WARN] state file does not exist yet, using counter 0')
        return 0
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

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((server_ip, server_port))

print '[INFO] Listening '+server_ip+':'+str(server_port)+' '+server_public_key.encode('hex')

command_regex = re.compile(r'^v01 knock (?P<client_ip>[0-9\. ]{15}) (?P<server_ip>[0-9\. ]{15}) (?P<counter>[0-9a-f]{32})      ([ ]{16})*$')

def parse_command(data):
    parts = command_regex.match(data)
    if not parts:
        return None
    return {
        'client_ip': parts.group('client_ip').strip(),
        'server_ip': parts.group('server_ip').strip(),
        'counter': int(parts.group('counter'), 16)
    }

PROTO_MIN_SIZE = pysodium.crypto_box_SEALBYTES + pysodium.crypto_sign_BYTES + 80

while True:
    try:
        cdata, (client_ip, client_port) = sock.recvfrom(1024)

        if len(cdata) < PROTO_MIN_SIZE:
            # normal: a UDP scan would cause this
            log('[INFO] small packet', client_ip, client_port)
            continue

        try:
            signed = pysodium.crypto_box_seal_open(cdata, server_public_key, server_private_key)
        except:
            # normal-ish: any big enough packet to the port will cause
            # this, but unless knockd happens to run on a common UDP
            # port there's not much reason to see such a big packet
            log('[INFO] incorrect ciphertext', client_ip, client_port)
            continue

        for sign_key in client_sign_keys:
            try:
                plain = pysodium.crypto_sign_open(signed, sign_key)
                break
            except:
                # not an issue if we have several candidate keys to check
                pass
        else:
            # Very unusual: someone knows the server public key but is
            # not a valid client. You should investigate how they came
            # to know that key.
            log('[SEVERE] bad signature', client_ip, client_port)
            continue

        command = parse_command(plain)
        if not command:
            # someone managed to sign an invalid command!?
            log('[SEVERE] bad command', client_ip, client_port, plain)
            continue

        if command['client_ip'] != client_ip:
            log('[POSSIBLE_REPLAY] bad client IP', client_ip, client_port, command)
            continue
        if command['server_ip'] != server_ip:
            log('[POSSIBLE_REPLAY] bad destination IP', client_ip, client_port, command)
            continue

        # FIXME: lock counter file

        if command['counter'] <= read_counter():
            log('[POSSIBLE_REPLAY] bad counter', client_ip, client_port, command)
            # FIXME: unlock counter file
            continue

        # Cool, write that counter ASAP so the packet can't be used again
        write_counter(command['counter'])

        # FIXME: unlock counter file

        # XXX: We *could* do a date check too, but previous checks
        # should be sufficient. There is more risk of server's clock
        # going wrong and the client getting locked out than benefit.

        log('[INFO] valid knock', client_ip, client_port, command)
        subprocess.Popen([knocked_command, client_ip])

    except KeyboardInterrupt:
        break

    except Exception as e:
        print 'packet exception ', e
        pass
