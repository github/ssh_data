module SSHData
  module PublicKey
    # Public key algorithm identifiers
    ALGO_RSA        = "ssh-rsa"
    ALGO_DSA        = "ssh-dss"
    ALGO_ECDSA256   = "ecdsa-sha2-nistp256"
    ALGO_ECDSA384   = "ecdsa-sha2-nistp384"
    ALGO_ECDSA521   = "ecdsa-sha2-nistp521"
    ALGO_ED25519    = "ssh-ed25519"
    ALGO_SKED25519  = "sk-ssh-ed25519@openssh.com"
    ALGO_SKECDSA256 = "sk-ecdsa-sha2-nistp256@openssh.com"

    # RSA SHA2 *signature* algorithms used with ALGO_RSA keys.
    # https://tools.ietf.org/html/draft-rsa-dsa-sha2-256-02
    ALGO_RSA_SHA2_256 = "rsa-sha2-256"
    ALGO_RSA_SHA2_512 = "rsa-sha2-512"

    ALGOS = [
      ALGO_RSA, ALGO_DSA, ALGO_ECDSA256, ALGO_ECDSA384, ALGO_ECDSA521,
      ALGO_ED25519, ALGO_SKECDSA256, ALGO_SKED25519
    ]

    # Parse an OpenSSH public key in authorized_keys format (see sshd(8) manual
    # page).
    #
    # key - An OpenSSH formatted public key, including algo, base64 encoded key
    #       and optional comment.
    #
    # Returns a PublicKey::Base subclass instance.
    def self.parse_openssh(key)
      algo, raw, _ = SSHData.key_parts(key)
      parsed = parse_rfc4253(raw)

      if parsed.algo != algo
        raise DecodeError, "algo mismatch: #{parsed.algo.inspect}!=#{algo.inspect}"
      end

      parsed
    end

    # Deprecated
    singleton_class.send(:alias_method, :parse, :parse_openssh)

    # Parse an RFC 4253 binary SSH public key.
    #
    # key - A RFC 4253 binary public key String.
    #
    # Returns a PublicKey::Base subclass instance.
    def self.parse_rfc4253(raw)
      data, read = Encoding.decode_public_key(raw)

      if read != raw.bytesize
        raise DecodeError, "unexpected trailing data"
      end

      from_data(data)
    end

    def self.from_data(data)
      case data[:algo]
      when ALGO_RSA
        RSA.new(**data)
      when ALGO_DSA
        DSA.new(**data)
      when ALGO_ECDSA256, ALGO_ECDSA384, ALGO_ECDSA521
        ECDSA.new(**data)
      when ALGO_ED25519
        ED25519.new(**data)
      when ALGO_SKED25519
        SKED25519.new(**data)
      when ALGO_SKECDSA256
        SKECDSA.new(**data)
      else
        raise DecodeError, "unkown algo: #{data[:algo].inspect}"
      end
    end
  end
end

require "ssh_data/public_key/base"
require "ssh_data/public_key/security_key"
require "ssh_data/public_key/rsa"
require "ssh_data/public_key/dsa"
require "ssh_data/public_key/ecdsa"
require "ssh_data/public_key/ed25519"
require "ssh_data/public_key/sked25519"
require "ssh_data/public_key/skecdsa"
