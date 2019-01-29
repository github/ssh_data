module SSHData
  module PrivateKey
    PEM_TYPE = "OPENSSH PRIVATE KEY"

    # Parse an SSH public key.
    #
    # key - An SSH formatted public key, including algo, encoded key and optional
    #       user/host names.
    #
    # Returns a PublicKey::Base subclass instance.
    def self.parse(key)
      raw = Encoding.decode_pem(key, PEM_TYPE)

      data, read = Encoding.decode_openssh_private_key(raw)
      unless read == raw.bytesize
        raise DecodeError, "unexpected trailing data"
      end

      from_data(data)
    end

    def self.from_data(data)
      case data[:algo]
      when PublicKey::ALGO_RSA
        RSA.new(**data)
      else
        raise DecodeError, "unkown algo: #{data[:algo].inspect}"
      end
    end
  end
end

require "ssh_data/private_key/base"
require "ssh_data/private_key/rsa"
