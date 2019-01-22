class SSHData::PublicKey
  # Public key algorithm identifiers
  ALGO_RSA      = "ssh-rsa"
  ALGO_DSA      = "ssh-dss"
  ALGO_ECDSA256 = "ecdsa-sha2-nistp256"
  ALGO_ECDSA384 = "ecdsa-sha2-nistp384"
  ALGO_ECDSA521 = "ecdsa-sha2-nistp521"
  ALGO_ED25519  = "ssh-ed25519"
end
