#!/usr/bin/env python

# This file is part of irods-nagios-plugin.
# SPDX-License-Identifier: GPL-3.0-or-later

from irods.session import iRODSSession
from irods.connection import Connection
import os
import re
import sys
import argparse
from cryptography import  x509
from cryptography.x509.extensions import SubjectAlternativeName, DNSName
from datetime import datetime, timezone


class AnonymousConnection(Connection):
    def _login_native(self, password=None):
        pass

def check_for_cert_name_and_expiration(irods_host, ssl_settings, port=1247, checkname=None, expiration=200, verbose=False ):
    now = datetime.now(timezone.utc)

    with iRODSSession(host=irods_host, port=port, user=None, password=None, zone=None, **ssl_settings) as session:
        pool = session.pool
        c = AnonymousConnection(pool, pool.account)
        certbytes = c.socket.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(certbytes)

        try:
            rdn = cert.subject.rfc4514_string().split(",",1)[0]
            hostname = re.compile(r"^CN=(.*)").match(rdn).group(1)
        except:
            hostname = "No subject name found in certificate"
        lifetime = cert.not_valid_after_utc-now

        if verbose:
            print(f"Host:                   {hostname}")
            print(f"Certificate ends:       {cert.not_valid_after_utc:%d-%m-%Y}")
            print(f"Certificate starts:     {cert.not_valid_before_utc:%d-%m-%Y}")
            print(f"Certificate expires in: {lifetime.days} days")

            try:
                alt = cert.extensions.get_extension_for_class(SubjectAlternativeName).value

                for dns in alt.get_values_for_type(DNSName):
                    print(f"Certificate alt name:   {dns}")
            except:
                print("No alt names found")

        error = 0
        if (hostname != checkname):
            status = f"Certificate hostname CRITICAL: Hostname {hostname} does not match target {checkname}. "
            error = 2
        else:
            status = "Certificate hostname OK. "

        if lifetime.days < expiration:
            status += f"SSL Critical: Certificate will expire in {lifetime.days} (less than {expiration})."
            error = 2
        else:
            status += f"SSL OK: Certificate expires in {lifetime.days} days."

        print(status)
        return error

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Check iRods server ssl certificate validity')

    parser.add_argument('hostname', type=str, help='iRods server to connect to.')
    parser.add_argument('--certname', type=str, help='Hostname to look for in certificate (default is same as hostname)')
    parser.add_argument('--expiration', type=int, default=14, help='Number of days that certificate needs to be valid (from now).')
    parser.add_argument('-v','--verbose', action="store_true", help='Verbose information on certificate')

    parser.add_argument('--client_server_negotiation', type=str, default='request_server_negotiation')
    parser.add_argument('--client_server_policy', type=str, default='CS_NEG_REQUIRE')
    parser.add_argument('--encryption_algorithm', type=str, default='AES-256-CBC')
    parser.add_argument('--encryption_key_size', type=int, default=32)
    parser.add_argument('--encryption_num_hash_rounds', type=int, default=16)
    parser.add_argument('--encryption_salt_size', type=int, default=8)

    args = parser.parse_args()
    checkname = args.certname if args.certname else args.hostname

    ssl_settings = {
        'client_server_negotiation': args.client_server_negotiation,
        'client_server_policy': args.client_server_policy,
        'encryption_algorithm': args.encryption_algorithm,
        'encryption_key_size': args.encryption_key_size,
        'encryption_num_hash_rounds': args.encryption_num_hash_rounds,
        'encryption_salt_size': args.encryption_salt_size,
    }


    sys.exit(check_for_cert_name_and_expiration(
        args.hostname, 
        ssl_settings,
        checkname=checkname, 
        expiration=args.expiration,
        verbose=args.verbose))