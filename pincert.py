#!/usr/bin/python

import tlslite
import hashlib
import urlparse
import socket


def genHash(cert):
    print cert.publicKey.n
    nbits = bytearray.fromhex(hex(cert.publicKey.n)[2:-1])
    ebits = bytearray.fromhex(hex(cert.publicKey.e)[2:-1])
    nbits = nbits + ebits
    return hashlib.sha256(nbits).hexdigest()


def getSigFromFile(fileName):
    ff = open(fileName).read()
    x509 = tlslite.X509()
    x509.parse(ff)
    # Sure would be swell to know the subject.Organization of this cert.
    # WOULDN'T IT, PYTHON!?
    return genHash(x509)


def getSigFromHost(urlPath):
    url = urlparse.urlparse(urlPath)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((url.netloc, 443))
    conn = tlslite.TLSConnection(sock)
    conn.handshakeClientCert()
    import pdb; pdb.set_trace()
    print conn.session.serverCertChain.x509List
    return genHash(conn.session.serverCertChain.x509List[0])


def main():
    #print getSigFromFile('server.crt')
    print getSigFromHost("https://firefox.com")

main()
