require "ssh_data/error"
require "ssh_data/encoding"

class SSHData
  TYPE_USER = 1
  TYPE_HOST = 2

  RSA_CERT_TYPE                 = "ssh-rsa-cert-v01@openssh.com"
  DSA_CERT_TYPE                 = "ssh-dss-cert-v01@openssh.com"
  ECDSA_SHA2_NISTP256_CERT_TYPE = "ecdsa-sha2-nistp256-cert-v01@openssh.com"
  ECDSA_SHA2_NISTP384_CERT_TYPE = "ecdsa-sha2-nistp384-cert-v01@openssh.com"
  ECDSA_SHA2_NISTP521_CERT_TYPE = "ecdsa-sha2-nistp521-cert-v01@openssh.com"
  ED25519_CERT_TYPE             = "ssh-ed25519-cert-v01@openssh.com"

  ECDSA_CERT_TYPES = [
    ECDSA_SHA2_NISTP256_CERT_TYPE,
    ECDSA_SHA2_NISTP384_CERT_TYPE,
    ECDSA_SHA2_NISTP521_CERT_TYPE
  ]
end
