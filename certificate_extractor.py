# Command line SSL server certificate dumping tool by Beta-TNT.
# extracting SSL server certificate (leaf certificate) from PCAP file.

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
    if len(sys_argv) <= 1:
        print("Usage: %s pcap_file_name [certificate_dir]" % os_path.split(__file__)[1])
        print("Print certificate(s) info extracted from pcap file in json format to stdout,")
        print("and ignore duplicated certificate(s).")
        print("Save certificate(s) into certificate_dir/[certificate_sha1].cer")
        print("Will not save cert file if certificate_dir is not specified, print info only in that case.")
        print("you can redirect stdout into a file for further uses.")
        exit()

    pcapFile, outputDir = [*sys_argv, ""][1:3]

    if outputDir and not os_path.isdir(outputDir):
        raise FileNotFoundError('output dir "%s" is not valid.')
    
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
                certHashes = {
                    'md5': md5(certBin).hexdigest(),
                    'sha1': sha1(certBin).hexdigest()
                }
                keyHash = certHashes.get(certFileName, certHashes['sha1'])
                if keyHash in hashList or not certBin: continue
                hashList.add(keyHash)
                print(
                    json_dumps(
                        {
                            **certHashes,
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
                if saveCert and outputDir:
                    open(
                        os_path.join(
                            outputDir,
                            keyHash + '.cer'
                        ),
                        'wb'
                    ).write(certBin)
        except:
            # just ignore errors
            continue
