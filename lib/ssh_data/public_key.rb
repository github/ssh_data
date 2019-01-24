module SSHData
  module PublicKey
    # Public key algorithm identifiers
    ALGO_RSA      = "ssh-rsa"
    ALGO_DSA      = "ssh-dss"
    ALGO_ECDSA256 = "ecdsa-sha2-nistp256"
    ALGO_ECDSA384 = "ecdsa-sha2-nistp384"
    ALGO_ECDSA521 = "ecdsa-sha2-nistp521"
    ALGO_ED25519  = "ssh-ed25519"

    # Parse an SSH public key.
    #
    # key - An SSH formatted public key, including algo, encoded key and optional
    #       user/host names.
    #
    # Returns a PublicKey::Base subclass instance.
    def self.parse(key)
      algo, b64, _ = key.split(" ", 3)
      if algo.nil? || b64.nil?
        raise DecodeError, "bad public key format"
      end

      raw = Base64.decode64(b64)
      data, read = Encoding.decode_public_key(raw)

      if read != raw.bytesize
        raise DecodeError, "unexpected trailing data"
      end

      if data[:algo] != algo
        raise DecodeError, "algo mismatch: #{data[:algo].inspect}!=#{algo.inspect}"
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
      else
        raise DecodeError, "unkown algo: #{data[:algo].inspect}"
      end
    end
  end
end

require "ssh_data/public_key/base"
require "ssh_data/public_key/rsa"
require "ssh_data/public_key/dsa"
require "ssh_data/public_key/ecdsa"
require "ssh_data/public_key/ed25519"
