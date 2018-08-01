import OpenSSL.crypto as SSL

MSCA_CSR_SIGNING_PATH = "{CERTREQ_CA}/certsrv/certfnsh.asp"
SIGNING_REQUEST_DATA = "Mode=newreq&CertRequest={CERT}&CertAttrib={CERTATTRIB}&TargetStoreFlags=0&SaveCert=yes&ThumbPrint="
CERTLINK="{CERTREQ_CA}/certsrv/${OUTPUTLINK}"

class PyCertReq():
    def __init__(self):
        pass

    def generate_certs(self, key_path, csr_path):
        pkey = SSL.PKey()
        pkey.generate_key(SSL.TYPE_RSA, 4096)

        with open(key_path, "w") as file:
            file.write(SSL.dump_privatekey(type=SSL.FILETYPE_PEM, pkey=pkey).decode())

        certificate = SSL.X509Req()
        certificate.sign(pkey=pkey, digest="md5")
        with open(csr_path, "w") as file:
            file.write(SSL.dump_certificate_request(type=SSL.FILETYPE_PEM, req=certificate).decode())

    def send_csr_for_signing(self, csr_path):
        pass
