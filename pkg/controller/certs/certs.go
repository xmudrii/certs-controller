package certs

import (
	"os"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/cli/genkey"
	"github.com/cloudflare/cfssl/signer/local"
	"github.com/cloudflare/cfssl/signer"
	"encoding/json"
	"io/ioutil"
)

// newCertificate returns signed certificate, in order, cert, key and csr.
func newCertificate(profile, caFile, caKeyFile string, csrBytes []byte) ([]byte, []byte, []byte, error) {
	req := csr.CertificateRequest{
		KeyRequest: csr.NewBasicKeyRequest(),
	}
	err := json.Unmarshal(csrBytes, &req)
	if err != nil {
		return nil, nil, nil, err
	}

	g := &csr.Generator{Validator: genkey.Validator}
	csrBytes, key, err := g.ProcessRequest(&req)
	if err != nil {
		key = nil
		return nil, nil, nil, err
	}

	s, err := local.NewSignerFromFile(caFile, caKeyFile, nil)
	if err != nil {
		return nil, nil, nil, err
	}

	var cert []byte
	signReq := signer.SignRequest{
		Request: string(csrBytes),
		Profile: profile,
	}

	cert, err = s.Sign(signReq)
	if err != nil {
		return nil, nil, nil, err
	}

	return cert, key, csrBytes, nil
}

func newCertificateWrapper(profile string, caBytes, caKeyBytes, csrBytes []byte) ([]byte, []byte, []byte, error) {
	caFile, err := writeTempFile(profile+".pem", caBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	defer os.Remove(caFile.Name())

	caKey, err := writeTempFile(profile+"-key.pem", caKeyBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	defer os.Remove(caKey.Name())

	return newCertificate(profile, caFile.Name(), caKey.Name(), csrBytes)
}

func writeTempFile(prefix string, content []byte) (*os.File, error) {
	file, err := ioutil.TempFile("", prefix)
	if err != nil {
		return nil, err
	}
	_, err = file.Write(content)
	if err != nil {
		return nil, err
	}

	return file, nil
}