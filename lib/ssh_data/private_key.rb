module SSHData
  module PrivateKey
    PEM_TYPE = "OPENSSH PRIVATE KEY"

    # Parse an SSH private key.
    #
    # key - An PEM encoded OpenSSH private key.
    #
    # Returns an Array of PrivateKey::Base subclass instances.
    def self.parse(key)
      raw = Encoding.decode_pem(key, PEM_TYPE)

      data, read = Encoding.decode_openssh_private_key(raw)
      unless read == raw.bytesize
        raise DecodeError, "unexpected trailing data"
      end

      from_data(data)
    end

    def self.from_data(data)
      data[:private_keys].map do |priv|
        case priv[:algo]
        when PublicKey::ALGO_RSA
          RSA.new(**priv)
        when PublicKey::ALGO_DSA
          DSA.new(**priv)
        else
          raise DecodeError, "unkown algo: #{priv[:algo].inspect}"
        end
      end
    end
  end
end

require "ssh_data/private_key/base"
require "ssh_data/private_key/rsa"
require "ssh_data/private_key/dsa"
