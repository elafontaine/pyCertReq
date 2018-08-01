import os
from unittest import TestCase
from pycertreq.pycertreq import *


def try_remove_file(file):
    try:
        os.remove(file)
    except:
        pass


"""
CERT="$( cat "${CERTREQ_WORKDIR}/${CERTREQ_CNPARAM}.crt" | tr -d '\n\r' )"
DATA="Mode=newreq&CertRequest=${CERT}&C&TargetStoreFlags=0&SaveCert=yes"
"""


def return_successful_response():
    return """
        function handleGetCert() {
            location="certnew.cer?ReqID=123456"
        }
        function getCertChain() {
            location="certnew.cer?ReqID=123456"
        }
        
    """


class TestPyCertReq(TestCase):
    def setUp(self):
        self.obj = PyCertReq()
        self.key_path = "./test.key"
        self.csr_path = "./test.csr"

    def tearDown(self):
        try_remove_file(self.key_path)
        try_remove_file(self.csr_path)

    def test_can_generate_certificate(self):
        self.obj.generate_certs(key_path=self.key_path, csr_path=self.csr_path)

        self.assertTrue(os.path.isfile(self.key_path))
        self.assertTrue(os.path.isfile(self.csr_path))

    def test_can_request_Microsoft_CA(self):
        # given : a Certificate Authority host
        self.MSCA_Host = "hostname"
        self.path_to_request = expected_path = "/path/on/CA"

        # when : making a request to the CA
        actual_responded_path = self.obj.send_csr_for_signing(csr_path=self.csr_path)

        """
        OUTPUTLINK="$( curl -k -u "${CERTREQ_USER}:${CERTREQ_PASS}" --ntlm \
        %s \
        -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
        -H 'Accept-Encoding: gzip, deflate' \
        -H 'Accept-Language: en-US,en;q=0.5' \
        -H 'Connection: keep-alive' \
        -H "Host: ${CERTREQ_CAHOST}" \
        -H "Referer: ${CERTREQ_CA}/certsrv/certrqxt.asp" \
        -H 'User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko' \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        --data %s | grep -A 1 'function handleGetCert() {' | tail -n 1 | cut -d '"' -f 2 )"
        """ % (MSCA_CSR_SIGNING_PATH, SIGNING_REQUEST_DATA)

        # then : my response should contain the path where the signed CA should be
        self.assertEqual(first=expected_path,
                         second=actual_responded_path,
                         msg="the path to the certificate wasn't the expected one")
