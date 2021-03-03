require "securerandom"
require "ipaddr"

module SSHData
  class Certificate
    # Special values for valid_before and valid_after.
    BEGINNING_OF_TIME = Time.at(0)
    END_OF_TIME = Time.at((2**64)-1)

    # Integer certificate types
    TYPE_USER = 1
    TYPE_HOST = 2

    # Certificate algorithm identifiers
    ALGO_RSA        = "ssh-rsa-cert-v01@openssh.com"
    ALGO_DSA        = "ssh-dss-cert-v01@openssh.com"
    ALGO_ECDSA256   = "ecdsa-sha2-nistp256-cert-v01@openssh.com"
    ALGO_ECDSA384   = "ecdsa-sha2-nistp384-cert-v01@openssh.com"
    ALGO_ECDSA521   = "ecdsa-sha2-nistp521-cert-v01@openssh.com"
    ALGO_ED25519    = "ssh-ed25519-cert-v01@openssh.com"
    ALGO_SKECDSA256 = "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com"
    ALGO_SKED25519  = "sk-ssh-ed25519-cert-v01@openssh.com"

    ALGOS = [
      ALGO_RSA, ALGO_DSA, ALGO_ECDSA256, ALGO_ECDSA384, ALGO_ECDSA521,
      ALGO_ED25519, ALGO_SKECDSA256, ALGO_SKED25519
    ]

    CRITICAL_OPTION_FORCE_COMMAND  = "force-command"
    CRITICAL_OPTION_SOURCE_ADDRESS = "source-address"

    attr_reader :algo, :nonce, :public_key, :serial, :type, :key_id,
                :valid_principals, :valid_after, :valid_before,
                :critical_options, :extensions, :reserved, :ca_key, :signature

    # Parse an OpenSSH certificate in authorized_keys format (see sshd(8) manual
    # page).
    #
    # cert              - An OpenSSH formatted certificate, including key algo,
    #                     base64 encoded key and optional comment.
    # unsafe_no_verify: - Bool of whether to skip verifying certificate signature
    #                     (Default false)
    #
    # Returns a Certificate instance.
    def self.parse_openssh(cert, unsafe_no_verify: false)
      algo, raw, _ = SSHData.key_parts(cert)
      parsed = parse_rfc4253(raw, unsafe_no_verify: unsafe_no_verify)

      if parsed.algo != algo
        raise DecodeError, "algo mismatch: #{parsed.algo.inspect}!=#{algo.inspect}"
      end

      parsed
    end

    # Deprecated
    singleton_class.send(:alias_method, :parse, :parse_openssh)

    # Parse an RFC 4253 binary SSH certificate.
    #
    # cert              - A RFC 4253 binary certificate String.
    # unsafe_no_verify: - Bool of whether to skip verifying certificate
    #                     signature (Default false)
    #
    # Returns a Certificate instance.
    def self.parse_rfc4253(raw, unsafe_no_verify: false)
      data, read = Encoding.decode_certificate(raw)

      if read != raw.bytesize
        raise DecodeError, "unexpected trailing data"
      end

      # Parse data into better types, where possible.
      public_key = PublicKey.from_data(data.delete(:public_key))
      ca_key     = PublicKey.from_data(data.delete(:signature_key))

      new(**data.merge(public_key: public_key, ca_key: ca_key)).tap do |cert|
        raise VerifyError unless unsafe_no_verify || cert.verify
      end
    end

    # Intialize a new Certificate instance.
    #
    # algo:             - The certificate's String algorithm id (one of ALGO_RSA,
    #                     ALGO_DSA, ALGO_ECDSA256, ALGO_ECDSA384, ALGO_ECDSA521,
    #                     or ALGO_ED25519)
    # nonce:            - The certificate's String nonce field.
    # public_key:       - The certificate's public key as an PublicKey::Base
    #                     subclass instance.
    # serial:           - The certificate's Integer serial field.
    # type:             - The certificate's Integer type field (one of TYPE_USER
    #                     or TYPE_HOST).
    # key_id:           - The certificate's String key_id field.
    # valid_principals: - The Array of Strings valid_principles field from the
    #                     certificate.
    # valid_after:      - The certificate's Time valid_after field.
    # valid_before:     - The certificate's Time valid_before field.
    # critical_options: - The Hash critical_options field from the certificate.
    # extensions:       - The Hash extensions field from the certificate.
    # reserved:         - The certificate's String reserved field.
    # ca_key:           - The issuing CA's public key as a PublicKey::Base
    #                     subclass instance.
    # signature:        - The certificate's String signature field.
    #
    # Returns nothing.
    def initialize(public_key:, key_id:, algo: nil, nonce: nil, serial: 0, type: TYPE_USER, valid_principals: [], valid_after: BEGINNING_OF_TIME, valid_before: END_OF_TIME, critical_options: {}, extensions: {}, reserved: "", ca_key: nil, signature: "")
      @algo = algo || Encoding::CERT_ALGO_BY_PUBLIC_KEY_ALGO[public_key.algo]
      @nonce = nonce || SecureRandom.random_bytes(32)
      @public_key = public_key
      @serial = serial
      @type = type
      @key_id = key_id
      @valid_principals = valid_principals
      @valid_after = valid_after
      @valid_before = valid_before
      @critical_options = critical_options
      @extensions = extensions
      @reserved = reserved
      @ca_key = ca_key
      @signature = signature
    end

    # OpenSSH certificate in authorized_keys format (see sshd(8) manual page).
    #
    # comment - Optional String comment to append.
    #
    # Returns a String key.
    def openssh(comment: nil)
      [algo, Base64.strict_encode64(rfc4253), comment].compact.join(" ")
    end

    # RFC4253 binary encoding of the certificate.
    #
    # Returns a binary String.
    def rfc4253
      Encoding.encode_fields(
        [:string,  algo],
        [:string,  nonce],
        [:raw,     public_key_without_algo],
        [:uint64,  serial],
        [:uint32,  type],
        [:string,  key_id],
        [:list,    valid_principals],
        [:time,    valid_after],
        [:time,    valid_before],
        [:options, critical_options],
        [:options, extensions],
        [:string,  reserved],
        [:string,  ca_key.rfc4253],
        [:string,  signature],
      )
    end

    # Sign this certificate with a private key.
    #
    # private_key - An SSHData::PrivateKey::Base subclass instance.
    # algo:       - Optionally specify the signature algorithm to use.
    #
    # Returns nothing.
    def sign(private_key, algo: nil)
      @ca_key = private_key.public_key
      @signature = private_key.sign(signed_data, algo: algo)
    end

    # Verify the certificate's signature.
    #
    # Returns boolean.
    def verify
      ca_key.verify(signed_data, signature)
    end

    # The force-command critical option, if present.
    #
    # Returns a String or nil.
    def force_command
      case value = critical_options[CRITICAL_OPTION_FORCE_COMMAND]
      when String, NilClass
        value
      else
        raise DecodeError, "bad force-request"
      end
    end

    # The source-address critical option, if present.
    #
    # Returns an Array of IPAddr instances or nil.
    def source_address
      return @source_address if defined?(@source_address)

      value = critical_options[CRITICAL_OPTION_SOURCE_ADDRESS]

      @source_address = case value
      when String
        value.split(",").map do |str_addr|
          begin
            IPAddr.new(str_addr.strip)
          rescue IPAddr::InvalidAddressError => e
            raise DecodeError, "bad source-address: #{e.message}"
          end
        end
      when NilClass
        nil
      else
        raise DecodeError, "bad source-address"
      end
    end

    # Check if the given IP address is allowed for use with this certificate.
    #
    # address - A String IP address.
    #
    # Returns boolean.
    def allowed_source_address?(address)
      return true if source_address.nil?
      parsed_addr = IPAddr.new(address)
      source_address.any? { |a| a.include?(parsed_addr) }
    rescue IPAddr::InvalidAddressError
      return false
    end

    private

    # The portion of the certificate over which the signature is calculated.
    #
    # Returns a binary String.
    def signed_data
      siglen = self.signature.bytesize + 4
      rfc4253.byteslice(0...-siglen)
    end

    # Helper for getting the RFC4253 encoded public key with the first field
    # (the algorithm) stripped off.
    #
    # Returns a String.
    def public_key_without_algo
      key = public_key.rfc4253
      _, algo_len = Encoding.decode_string(key)
      key.byteslice(algo_len..-1)
    end

  end
end
