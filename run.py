#!/usr/bin/env python3

import dns.message
import os
import shutil
import socket
import string
import subprocess
import time

net = '172.31.91.'

zoneOwners = {
    '.': ('auth_root', 3),
    'com.': ('auth_com', 4),
    'example.com.': ('auth_example.com', 5),
}

def runInContainer(cont, cmd, input=None):
    print(f'> {cont}$ {cmd}')
    output = subprocess.check_output(f'docker-compose exec {cont} {cmd}', shell=True)
    print(output)
    print('<')

    return output

def sendUDPQuery(ipsuffix, query, timeout=2.0, decode=True, fwparams=dict()):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    sock.connect((f'{net}{ipsuffix}', 53))

    if timeout:
        sock.settimeout(timeout)

    try:
        sock.send(query.to_wire())
        data = sock.recv(4096)
    except socket.timeout:
        data = None
    finally:
        if timeout:
            sock.settimeout(None)

    message = None
    if data:
        if not decode:
            return data
        message = dns.message.from_wire(data, **fwparams)
    return message

def query(ipsuffix, name, type):
    query = dns.message.make_query(name, type)
    return sendUDPQuery(ipsuffix, query)


def main():
    os.system('docker-compose rm --force --stop')

    shutil.rmtree('data')
    os.mkdir('data')
    for k,v in zoneOwners.items():
        dir, ipsuffix = v
        os.mkdir('data/'+dir)

    with subprocess.Popen(['docker-compose','up']) as compose:
        try:
            time.sleep(5)
            runInContainer('auth_root', 'pdnsutil load-zone . /etc/powerdns/pdns.d/root.zone')
            runInContainer('auth_root', 'pdnsutil secure-zone .')
            anchors = open('data/anchors', 'wb')
            anchors.write(runInContainer('auth_root', 'pdnsutil export-zone-ds .'))
            anchors.close()

            runInContainer('auth_com', 'pdnsutil load-zone com. /etc/powerdns/pdns.d/com.zone')
            time.sleep(5)
            os.system('docker-compose restart recursor')
            
            """
   ----------------------------------------------------------------
    initial              new RRSIGs           new DNSKEY
   ----------------------------------------------------------------
   Parent:
    SOA_0 -------------------------------------------------------->
    RRSIG_par(SOA) ----------------------------------------------->
    DS_K_1 ------------------------------------------------------->
    RRSIG_par(DS_K_1) -------------------------------------------->

   Child:
    SOA_0                SOA_1                SOA_2
    RRSIG_Z_10(SOA)      RRSIG_Z_10(SOA)      RRSIG_Z_10(SOA)
                         RRSIG_Z_11(SOA)      RRSIG_Z_11(SOA)

    DNSKEY_K_1           DNSKEY_K_1           DNSKEY_K_1
                                              DNSKEY_K_2
    DNSKEY_Z_10          DNSKEY_Z_10          DNSKEY_Z_10
                                              DNSKEY_Z_11
    RRSIG_K_1(DNSKEY)    RRSIG_K_1(DNSKEY)    RRSIG_K_1(DNSKEY)
                                              RRSIG_K_2(DNSKEY)
            """

            # initial
            runInContainer('auth_example.com', 'pdnsutil create-zone example.com')
            print(query(5, 'example.com', 'SOA'))
            runInContainer('auth_example.com', 'pdnsutil replace-rrset example.com "" SOA 20 "ns1.example.com root.example.com 2000 1200 60 1209600 30"')
            oldKSKid = int(runInContainer('auth_example.com', 'pdnsutil add-zone-key example.com KSK 2048 active published rsasha1-nsec3-sha1').split(b'\n')[-2])
            oldZSKid = int(runInContainer('auth_example.com', 'pdnsutil add-zone-key example.com ZSK 2048 active published rsasha1-nsec3-sha1').split(b'\n')[-2])

            # new RRSIGs
            newKSKid = int(runInContainer('auth_example.com', 'pdnsutil add-zone-key example.com KSK active unpublished ecdsa384').split(b'\n')[-2])
            newZSKid = int(runInContainer('auth_example.com', 'pdnsutil add-zone-key example.com ZSK active unpublished ecdsa384').split(b'\n')[-2])

            # new DNSKEY
            runInContainer('auth_example.com', f'pdnsutil publish-zone-key example.com {newKSKid}')
            runInContainer('auth_example.com', f'pdnsutil publish-zone-key example.com {newZSKid}')

            """
   ----------------------------------------------------------------
    new DS               DNSKEY removal       RRSIGs removal
   ----------------------------------------------------------------
   Parent:
    SOA_1 ------------------------------------------------------->
    RRSIG_par(SOA) ---------------------------------------------->
    DS_K_2 ------------------------------------------------------>
    RRSIG_par(DS_K_2) ------------------------------------------->

   Child:
    -------------------> SOA_3                SOA_4
    -------------------> RRSIG_Z_10(SOA)
    -------------------> RRSIG_Z_11(SOA)      RRSIG_Z_11(SOA)

    ------------------->
    -------------------> DNSKEY_K_2           DNSKEY_K_2
    ------------------->
    -------------------> DNSKEY_Z_11          DNSKEY_Z_11
    ------------------->
    -------------------> RRSIG_K_2(DNSKEY)    RRSIG_K_2(DNSKEY)
   ----------------------------------------------------------------
            """

            # new DS
            # ....

            # DNSKEY removal
            runInContainer('auth_example.com', f'pdnsutil unpublish-zone-key example.com {oldKSKid}')
            runInContainer('auth_example.com', f'pdnsutil unpublish-zone-key example.com {oldZSKid}')

            # RRSIGs removal
            runInContainer('auth_example.com', f'pdnsutil deactivate-zone-key example.com {oldKSKid}')
            runInContainer('auth_example.com', f'pdnsutil deactivate-zone-key example.com {oldZSKid}')

            print("done, push Enter")
            input()
        finally:
            compose.terminate()

if __name__ == '__main__':
    main()