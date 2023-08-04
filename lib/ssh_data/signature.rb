# frozen_string_literal: true

module SSHData
  class Signature
    PEM_TYPE = "SSH SIGNATURE"
    SIGNATURE_PREAMBLE = "SSHSIG"
    MIN_SUPPORTED_VERSION = 1
    MAX_SUPPORTED_VERSION = 1

    # Spec: no SHA1 or SHA384. In practice, OpenSSH is always going to use SHA512.
    # Note the actual signing / verify primitive may use a different hash algorithm.
    # https://github.com/openssh/openssh-portable/blob/b7ffbb17e37f59249c31f1ff59d6c5d80888f689/PROTOCOL.sshsig#L67
    SUPPORTED_HASH_ALGORITHMS = {
      "sha256" => OpenSSL::Digest::SHA256,
      "sha512" => OpenSSL::Digest::SHA512,
    }

    PERMITTED_RSA_SIGNATURE_ALGORITHMS = [
      PublicKey::ALGO_RSA_SHA2_256,
      PublicKey::ALGO_RSA_SHA2_512,
    ]

    attr_reader :sigversion, :namespace, :signature, :reserved, :hash_algorithm

    # Parses a PEM armored SSH signature.
    # pem - A PEM encoded SSH signature.
    #
    # Returns a Signature instance.
    def self.parse_pem(pem)
      pem_type = Encoding.pem_type(pem)

      if pem_type != PEM_TYPE
        raise DecodeError, "Mismatched PEM type. Expecting '#{PEM_TYPE}', actually '#{pem_type}'."
      end

      blob = Encoding.decode_pem(pem, pem_type)
      self.parse_blob(blob)
    end

    def self.parse_blob(blob)
      data, read = Encoding.decode_openssh_signature(blob)

      if read != blob.bytesize
        raise DecodeError, "unexpected trailing data"
      end

      new(**data)
    end

    def initialize(sigversion:, publickey:, namespace:, reserved:, hash_algorithm:, signature:)
      if sigversion > MAX_SUPPORTED_VERSION || sigversion < MIN_SUPPORTED_VERSION
        raise UnsupportedError, "Signature version is not supported"
      end

      unless SUPPORTED_HASH_ALGORITHMS.has_key?(hash_algorithm)
        raise UnsupportedError, "Hash algorithm #{hash_algorithm} is not supported."
      end

      # Spec: empty namespaces are not permitted.
      # https://github.com/openssh/openssh-portable/blob/b7ffbb17e37f59249c31f1ff59d6c5d80888f689/PROTOCOL.sshsig#L57
      raise UnsupportedError, "A namespace is required." if namespace.empty?

      # Spec: ignore 'reserved', don't need to validate that it is empty.

      @sigversion = sigversion
      @publickey = publickey
      @namespace = namespace
      @reserved = reserved
      @hash_algorithm = hash_algorithm
      @signature = signature
    end

    def verify(signed_data, **opts)
      signing_key = public_key

      # Unwrap the signing key if this signature was created from a certificate.
      key = signing_key.is_a?(Certificate) ? signing_key.public_key : signing_key

      digest_algorithm = SUPPORTED_HASH_ALGORITHMS[@hash_algorithm]

      if key.is_a?(PublicKey::RSA)
        sig_algo, * = Encoding.decode_signature(@signature)

        # Spec: If the signature is an RSA signature, the legacy 'ssh-rsa'
        # identifer is not permitted.
        # https://github.com/openssh/openssh-portable/blob/b7ffbb17e37f59249c31f1ff59d6c5d80888f689/PROTOCOL.sshsig#L72
        unless PERMITTED_RSA_SIGNATURE_ALGORITHMS.include?(sig_algo)
          raise UnsupportedError, "RSA signature #{sig_algo} is not supported."
        end
      end

      message_digest = digest_algorithm.digest(signed_data)
      blob =
        SIGNATURE_PREAMBLE +
        Encoding.encode_string(@namespace) +
        Encoding.encode_string(@reserved || "") +
        Encoding.encode_string(@hash_algorithm) +
        Encoding.encode_string(message_digest)

      if key.class.include?(::SSHData::PublicKey::SecurityKey)
        key.verify(blob, @signature, **opts)
      else
        key.verify(blob, @signature)
      end
    end

    # Gets the public key from the signature.
    # If the signature was created from a certificate, this will be an
    # SSHData::Certificate. Otherwise, this will be a PublicKey algorithm.
    def public_key
      @data_public_key ||= load_public_key
    end

    private def load_public_key
      public_key_algorithm, _ = Encoding.decode_string(@publickey)

      if PublicKey::ALGOS.include?(public_key_algorithm)
        PublicKey.parse_rfc4253(@publickey)
      elsif Certificate::ALGOS.include?(public_key_algorithm)
        Certificate.parse_rfc4253(@publickey)
      else
        raise UnsupportedError, "Public key algorithm #{public_key_algorithm} is not supported."
      end
    end
  end
end
