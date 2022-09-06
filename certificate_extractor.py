# Command line SSL server certificate dumping tool by Beta-TNT.
# extracting SSL server certificate (leaf certificate) from PCAP file.

# usage: certificate_extractor.py pcap_file_name [certificate_dir]

# prints certificate info in json format to stdout, ignores duplicated certificate(s).
# and saves certificate binaries into certificate_dir/[certificate_md5].cer
# if certificate_dir not provided or invalid, will uses dirname(pcap_file_name) as default
# you can redirect stdout into a file for further uses.

from pyshark import FileCapture
from hashlib import md5, sha1
from os import path as os_path
from sys import argv as sys_argv
from json import dumps as json_dumps

hashList = set()
saveCert = True
certFileName = 'sha1'
abandonFields = [
    '',
    'handshake_certificate',
    'pkcs1_modulus',
    'x509af_encrypted'
]

if __name__== '__main__':
    pcapFile = sys_argv[1]
    outputDir = sys_argv[2] if len(sys_argv)>=3 and os_path.isdir(sys_argv[2]) else os_path.dirname(pcapFile)
    
    for pkt in filter(lambda pkt:"tls" in pkt, FileCapture(pcapFile)):
        try:
            tlsLayer = pkt['tls']
            if all(
                [
                    getattr(tlsLayer, 'record_content_type', False) == '22', # Record Content type Handshake
                    getattr(tlsLayer, 'handshake_type', False) == '11', # Handshake type Server Certificate
                    hasattr(tlsLayer, 'handshake_certificate') # Server Certificate binary
                ]
            ):
                certBin = bytes.fromhex(tlsLayer.handshake_certificate.replace(':',""))
                certMd5 = md5(certBin).hexdigest()
                certSha1 = sha1(certBin).hexdigest()
                if certMd5 in hashList or not certBin: continue
                hashList.add(certMd5)
                print(
                    json_dumps(
                        {
                            'md5': certMd5,
                            'sha1': certSha1,
                            **{
                                fieldName: getattr(
                                    tlsLayer,
                                    fieldName
                                ) for fieldName in tlsLayer.field_names if hasattr(
                                    tlsLayer,
                                    fieldName
                                ) and fieldName not in abandonFields
                            }
                        },
                        ensure_ascii=False
                    )
                )
                if saveCert:
                    open(
                        os_path.join(
                            outputDir,
                            {
                                'md5': certMd5,
                                'sha1': certSha1
                            }.get(certFileName, certSha1) + '.cer'
                        ),
                        'wb'
                    ).write(certBin)
        except:
            # just ignore errors
            continue
