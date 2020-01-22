#!/usr/bin/python3

#-------------------------------------------------------------------------------

import inspect
import argparse
import collections
from io import StringIO
import os
import re
import shutil
import socket
import subprocess
import sys

#-------------------------------------------------------------------------------

options = None
openssl = '/usr/bin/openssl'

extension_section = 'v3_req'
subject_alt_name_section = 'alt_names'
distinguished_name_section = 'req_distinguished_name'


default_ca_subject = 'CA-jvlcek'
cacert_filename = 'ca-cert.pem'
cakey_filename = 'ca-key.pem'
serial_filename = 'serial'
extensions_config_filename = 'extensions.conf'

#-------------------------------------------------------------------------------

def call_openssl(operation, args=[]):
    cmd_args = [openssl, operation] + args
    print(' '.join(cmd_args))

    p = subprocess.Popen(cmd_args,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)

    stdout, stderr = p.communicate()
    if p.returncode != 0:
        raise subprocess.CalledProcessError(returncode=p.returncode,
                                            cmd=' '.join(cmd_args),
                                            output=stderr)

    return stdout


#-------------------------------------------------------------------------------

class CA(object):
    def __init__(self, dir):
        print("\nJJV 000 : %s\n " % (inspect.stack()[0].function), flush=True)
        self.dir = dir
        self.hostname = None
        self.fqdn = None
        self.cacert_pathname = None
        self.cakey_pathname = None
        self.serial_pathname = None
        self.extensions_config_pathname = None
        self.cert_request_pathname = None


    def initialize(self, ca_subject=None):
        print("\nJJV 000 : %s\n " % (inspect.stack()[0].function), flush=True)

        self.hostname = socket.gethostname()
        self.fqdn = socket.getfqdn()
        self.cakey_pathname = os.path.join(self.dir, cakey_filename)
        self.cacert_pathname = os.path.join(self.dir, cacert_filename)
        self.serial_pathname = os.path.join(self.dir, serial_filename)
        self.extensions_config_pathname = os.path.join(self.dir, extensions_config_filename)
        self.cert_request_pathname = os.path.join(self.dir, 'cert_request')


        if os.path.exists(self.dir):
            if os.path.isdir(self.dir):
                pass
            else:
                raise ValueError('cert directory "%s" exists'
                                 'but is not a directory' % self.dir)
            if options.clean:
                shutil.rmtree(self.dir)
                os.makedirs(self.dir)
        else:
            os.makedirs(self.dir)

        if not os.path.exists(self.cacert_pathname) or not os.path.exists(self.cakey_pathname):
            self.create_serial()
            if ca_subject is None:
                ca_subject = default_ca_subject
            self.create_ca_cert(self.cakey_pathname, self.cacert_pathname, ca_subject)

    def create_serial(self, serial=None):
        print("\nJJV 000 : %s\n " % (inspect.stack()[0].function), flush=True)
        if serial is None:
            serial = '02'
        f = open(self.serial_pathname, 'w')
        f.write(serial)
        f.close()


    def create_key(self, key_pathname):
        print("\nJJV 000 : %s\n " % (inspect.stack()[0].function), flush=True)
        args = ['-out', key_pathname,
                str(options.key_bits)
            ]

        call_openssl('genrsa', args)

    def get_key_cert_filenames(self, subject):
        print("\nJJV 000 : %s\n " % (inspect.stack()[0].function), flush=True)
        if options.self_sign:
            key_filename = '%s-selfsign-key.pem' % subject
            cert_filename = '%s-selfsign-cert.pem' % subject
            p12_filename = '%s-selfsign.p12' % subject
        else:
            key_filename = '%s-key.pem' % subject
            cert_filename = '%s-cert.pem' % subject
            p12_filename = '%s.p12' % subject

        return key_filename, cert_filename, p12_filename

    def create_ca_cert(self, key_pathname, cert_pathname, subject, days=None):
        print("\nJJV 000 : %s\n " % (inspect.stack()[0].function), flush=True)
        if days is None:
            days = options.days

        args = ['-x509',
                '-new',
                '-key', key_pathname,
                '-out', cert_pathname,
                '-set_serial', '1',
                '-nodes',               # do not password protect key
                '-days', str(days),
                '-subj', '/CN=%s' % subject,
        ]

        self.create_key(key_pathname)
        call_openssl('req', args)

    def create_cert_request(self, key_pathname, subject):
        print("\nJJV 000 : %s\n " % (inspect.stack()[0].function), flush=True)
        self.create_key(key_pathname)
        args = ['-new',
                '-nodes',
                '-key', key_pathname,
                '-subj', '/CN=%s' % subject, 
                '-out', self.cert_request_pathname
                ]
        call_openssl('req', args)
        return self.cert_request_pathname

    def create_cert(self, subject, days=None):
        print("\nJJV 000 : %s\n " % (inspect.stack()[0].function), flush=True)
        if days is None:
            days = options.days

        key_filename, cert_filename, p12_filename = self.get_key_cert_filenames(subject)

        key_pathname = os.path.join(self.dir, key_filename)
        cert_pathname = os.path.join(self.dir, cert_filename)

        cert_request_pathname = self.create_cert_request(key_pathname, subject)

        args = ['-req',
                '-in', cert_request_pathname,
                '-CAkey', self.cakey_pathname,
                '-CA', self.cacert_pathname,
                '-CAserial', self.serial_pathname,
                '-CAcreateserial',
                '-out', cert_pathname,
                '-extfile', self.extensions_config_pathname,
                '-days', str(days),
        ]

        call_openssl('x509', args)

        return key_pathname, cert_pathname, p12_filename

    def create_self_signed_cert(self, subject, days=None):
        print("\nJJV 000 : %s\n " % (inspect.stack()[0].function), flush=True)
        if days is None:
            days = options.days

        key_filename, cert_filename, p12_filename = self.get_key_cert_filenames(subject)

        key_pathname = os.path.join(self.dir, key_filename)
        cert_pathname = os.path.join(self.dir, cert_filename)

        cert_request_pathname = self.create_cert_request(key_pathname, subject)

        args = ['-req',
                '-signkey', key_pathname,
                '-in', cert_request_pathname,
                '-out', cert_pathname,
                '-extfile', self.extensions_config_pathname,
                '-days', str(days),
        ]

        call_openssl('x509', args)

        return key_pathname, cert_pathname, p12_filename

    def create_p12(self, subject, key_pathname, cert_pathname, p12_filename):
        print("\nJJV 000 : %s\n " % (inspect.stack()[0].function), flush=True)
        p12_pathname = os.path.join(self.dir, p12_filename)
        args = ['-export',
                '-name', subject,
                '-passout', 'pass:%s' % options.p12_passwd,
                '-in', cert_pathname,
                '-inkey', key_pathname,
                '-out', p12_pathname,
                ]

        call_openssl('pkcs12', args)

    def show_cert(self, cert_file=None):
        print("\nJJV 000 : %s\n " % (inspect.stack()[0].function), flush=True)
        if cert_file is None:
            cert_file = os.path.join(self.dir,  options.cert_file)

        args = ['-in' , cert_file, '-text']

        print(call_openssl('x509', args))

    def get_subject_alt_names(self, subject, san):
        print("\nJJV 000 : %s\n " % (inspect.stack()[0].function), flush=True)
        subject_alt_names = collections.OrderedDict()

        subject_alt_names[subject] = None
        if san:
            for name in san:
                subject_alt_names[name] = None
                
        if options.fqdn_san:
            subject_alt_names[self.fqdn] = None
            
        return subject_alt_names.keys()


    def create_extension_config_file(self, subject_alt_names=None):
        print("\nJJV 000 : %s\n " % (inspect.stack()[0].function), flush=True)
        print("\nJJV 000 : %s subject_alt_names: \n%s" % (inspect.stack()[0].function, subject_alt_names), flush=True)

        f = StringIO()

        f.write('extensions = %s\n\n' % (extension_section))
        f.write('[%s]\n' % (extension_section))
        if subject_alt_names:
            f.write('subjectAltName = @%s\n' % (subject_alt_name_section))
            f.write('\n')

            f.write('[%s]\n' % (subject_alt_name_section))
            for i, san in enumerate(subject_alt_names):
                f.write('DNS.%d=%s\n' % (i+1, san))
            f.write('\n')

        string = f.getvalue()
        f.close()

        if options.verbose:
            print(string)

        f = open(self.extensions_config_pathname, 'w')
        f.write(string)
        f.close()
        
#-------------------------------------------------------------------------------

def main():
    print("\nJJV A00 : %s\n " % (inspect.stack()[0].function), flush=True)
    global options

    # --- cmd ---
    parser = argparse.ArgumentParser(description='create cert with openssl')

    parser.add_argument('-v', '--verbose', action='store_true',
                        help='be chatty')

    parser.add_argument('--clean', action='store_true',
                        help='remove contents of cert directory, reinitialize')

    parser.add_argument('--dir', default=os.path.join(os.path.expanduser('~'),'openssl-certs'),
                        help='ouput directory')

    parser.add_argument('-s', '--subject', required=True,
                        help='cert subject')

    parser.add_argument('--san', action='append',
                        help='subject alt name(s)')

    parser.add_argument('--fqdn-san', action='store_true',
                        help='add the fqdn to the Subject Alt Names')

    parser.add_argument('--key-bits', type=int,
                        help='number of bits in key')

    parser.add_argument('--days', type=int,
                        help='number of days cert is valid')

    parser.add_argument('--self-sign', action='store_true',
                        help='create a self-signed cert instead of using CA')

    parser.add_argument('--p12-passwd',
                        help='password for pkcs12 file')

    parser.set_defaults(subject=None,
                        config_file='openssl.conf',
                        key_file='key.pem',
                        cert_file='cert.pem',
                        key_bits = 2048,
                        days = 365*5,
                        self_signed=False,
                        p12_passwd='p12-passwd'
                    )

    # --- main ---
    options = parser.parse_args()

    try:

        print("\nJJV 000 : %s\n " % (inspect.stack()[0].function), flush=True)
        ca = CA(options.dir)
        print("\nJJV 000.1 : %s\n " % (inspect.stack()[0].function), flush=True)
        ca.initialize()
        print("\nJJV 000.2 : %s\n " % (inspect.stack()[0].function), flush=True)

        if options.subject is None:
            subject = ca.hostname
        else:
            subject = options.subject
    
        print("\nJJV 001 : %s\n " % (inspect.stack()[0].function), flush=True)
        subject_alt_names = ca.get_subject_alt_names(subject, options.san)
        print("\nJJV 002 : %s\n " % (inspect.stack()[0].function), flush=True)
        ca.create_extension_config_file(subject_alt_names)

        print("\nJJV 003 : %s\n " % (inspect.stack()[0].function), flush=True)
        if options.self_sign:
            key_pathname, cert_pathname, p12_filename = ca.create_self_signed_cert(subject)
        else:
            key_pathname, cert_pathname, p12_filename = ca.create_cert(subject)

        print("\nJJV 004 : %s\n " % (inspect.stack()[0].function), flush=True)
        ca.create_p12(subject, key_pathname, cert_pathname, p12_filename)

        print("\nJJV 005 : %s\n " % (inspect.stack()[0].function), flush=True)
        ca.show_cert(cert_pathname)

    except subprocess.CalledProcessError as e:
        print("\nJJV 006 : %s\n " % (inspect.stack()[0].function), flush=True)
        print("ERROR: %s" % (e), file=sys.stderr)
        print(e.output, file=sys.stderr)
        return 1

    print("\nJJV 007 : %s\n " % (inspect.stack()[0].function), flush=True)
    return 0

#-------------------------------------------------------------------------------

if __name__ == '__main__':
    sys.exit(main())
