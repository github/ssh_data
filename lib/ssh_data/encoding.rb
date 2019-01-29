module SSHData
  module Encoding
    # Fields in an OpenSSL private key
    # https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
    OPENSSH_PRIVATE_KEY_MAGIC = "openssh-key-v1\x00"
    OPENSSH_PRIVATE_KEY_FIELDS = [
      [:ciphername, :string],
      [:kdfname,    :string],
      [:kdfoptions, :string],
      [:nkeys,      :uint32],
    ]

    # Fields in an RSA private key
    RSA_PRIVATE_KEY_FIELDS = [
      [:n,       :mpint],
      [:e,       :mpint],
      [:d,       :mpint],
      [:iqmp,    :mpint],
      [:p,       :mpint],
      [:q,       :mpint],
    ]

    # Fields in an RSA public key
    RSA_KEY_FIELDS = [
      [:e, :mpint],
      [:n, :mpint]
    ]

    # Fields in a DSA public key
    DSA_KEY_FIELDS = [
      [:p, :mpint],
      [:q, :mpint],
      [:g, :mpint],
      [:y, :mpint]
    ]

    # Fields in an ECDSA public key
    ECDSA_KEY_FIELDS = [
      [:curve,      :string],
      [:public_key, :string]
    ]

    # Fields in a ED25519 public key
    ED25519_KEY_FIELDS = [
      [:pk, :string]
    ]

    PUBLIC_KEY_ALGO_BY_CERT_ALGO = {
      Certificate::ALGO_RSA      => PublicKey::ALGO_RSA,
      Certificate::ALGO_DSA      => PublicKey::ALGO_DSA,
      Certificate::ALGO_ECDSA256 => PublicKey::ALGO_ECDSA256,
      Certificate::ALGO_ECDSA384 => PublicKey::ALGO_ECDSA384,
      Certificate::ALGO_ECDSA521 => PublicKey::ALGO_ECDSA521,
      Certificate::ALGO_ED25519  => PublicKey::ALGO_ED25519,
    }

    KEY_FIELDS_BY_PUBLIC_KEY_ALGO = {
      PublicKey::ALGO_RSA      => RSA_KEY_FIELDS,
      PublicKey::ALGO_DSA      => DSA_KEY_FIELDS,
      PublicKey::ALGO_ECDSA256 => ECDSA_KEY_FIELDS,
      PublicKey::ALGO_ECDSA384 => ECDSA_KEY_FIELDS,
      PublicKey::ALGO_ECDSA521 => ECDSA_KEY_FIELDS,
      PublicKey::ALGO_ED25519  => ED25519_KEY_FIELDS,
    }

    KEY_FIELDS_BY_PRIVATE_KEY_ALGO = {
      PublicKey::ALGO_RSA => RSA_PRIVATE_KEY_FIELDS,
    }

    # Get the raw data from a PEM encoded blob.
    #
    # pem  - The PEM encoded String to decode.
    # type - The String PEM type we're expecting.
    #
    # Returns the decoded String.
    def decode_pem(pem, type)
      lines = pem.split("\n")

      unless lines.shift == "-----BEGIN #{type}-----"
        raise DecodeError, "bad PEM header"
      end

      unless lines.pop == "-----END #{type}-----"
        raise DecodeError, "bad PEM footer"
      end

      Base64.strict_decode64(lines.join)
    end

    # Decode an OpenSSH private key.
    #
    # raw - The binary String private key.
    #
    # Returns an Array containing a Hash describing the private key and the
    # Integer number of bytes read.
    def decode_openssh_private_key(raw)
      total_read = 0

      magic = raw.byteslice(0, total_read + OPENSSH_PRIVATE_KEY_MAGIC.bytesize)
      total_read += OPENSSH_PRIVATE_KEY_MAGIC.bytesize
      unless magic == OPENSSH_PRIVATE_KEY_MAGIC
        raise DecodeError, "bad OpenSSH private key"
      end

      data, read = decode_fields(raw, OPENSSH_PRIVATE_KEY_FIELDS, total_read)
      total_read += read

      # TODO: add support for encrypted private keys
      unless data[:ciphername] == "none" && data[:kdfname] == "none"
        raise DecryptError, "cannot decode encrypted private keys"
      end

      data[:public_keys], read = decode_n_strings(raw, data[:nkeys], total_read)
      total_read += read

      privs, read = decode_string(raw, total_read)
      total_read += read

      privs_read = 0

      checkint1, read = decode_uint32(privs, privs_read)
      privs_read += read

      checkint2, read = decode_uint32(privs, privs_read)
      privs_read += read

      unless checkint1 == checkint2
        raise DecryptError, "bad private key checksum"
      end

      data[:private_keys] = data[:nkeys].times.map do
        algo, read = decode_string(privs, privs_read)
        privs_read += read

        unless fields = KEY_FIELDS_BY_PRIVATE_KEY_ALGO[algo]
          raise AlgorithmError, "unknown algorithm: #{algo.inspect}"
        end

        priv_data, read = decode_fields(privs, fields, privs_read)
        privs_read += read

        comment, read = decode_string(privs, privs_read)
        privs_read += read

        priv_data.merge(algo: algo, comment: comment)
      end

      # padding at end is bytes 1, 2, 3, 4, etc...
      padding = privs.byteslice(privs_read..-1)
      unless padding.bytes.each_with_index.all? { |b, i| b == (i + 1) % 255 }
        raise DecodeError, "bad padding: #{padding.inspect}"
      end

      [data, total_read]
    end

    # Decode the signature.
    #
    # raw    - The binary String signature as described by RFC4253 section 6.6.
    # offset - Integer number of bytes into `raw` at which we should start
    #          reading.
    #
    # Returns an Array containing the decoded algorithm String, the decoded binary
    # signature String, and the Integer number of bytes read.
    def decode_signature(raw, offset=0)
      total_read = 0

      algo, read = decode_string(raw, offset + total_read)
      total_read += read

      sig, read = decode_string(raw, offset + total_read)
      total_read += read

      [algo, sig, total_read]
    end

    # Encoding a signature.
    #
    # algo       - The String signature algorithm.
    # signature  - The String signature blob.
    #
    # Returns an encoded String.
    def encode_signature(algo, signature)
      encode_string(algo) + encode_string(signature)
    end

    # Decode the fields in a public key.
    #
    # raw    - Binary String public key as described by RFC4253 section 6.6.
    # algo   - String public key algorithm identifier (optional).
    # offset - Integer number of bytes into `raw` at which we should start
    #          reading.
    #
    # Returns an Array containing a Hash describing the public key and the
    # Integer number of bytes read.
    def decode_public_key(raw, algo=nil, offset=0)
      total_read = 0

      if algo.nil?
        algo, read = decode_string(raw, offset + total_read)
        total_read += read
      end

      unless fields = KEY_FIELDS_BY_PUBLIC_KEY_ALGO[algo]
        raise AlgorithmError, "unknown algorithm: #{algo}"
      end

      data, read = decode_fields(raw, fields, offset + total_read)
      total_read += read

      data[:algo] = algo

      [data, total_read]
    end

    # Decode the fields in a certificate.
    #
    # raw    - Binary String certificate as described by RFC4253 section 6.6.
    # offset - Integer number of bytes into `raw` at which we should start
    #          reading.
    #
    # Returns an Array containing a Hash describing the certificate and the
    # Integer number of bytes read.
    def decode_certificate(raw, offset=0)
      total_read = 0

      data, read = decode_fields(raw, [
        [:algo,  :string],
        [:nonce, :string],
      ], offset + total_read)
      total_read += read

      unless key_algo = PUBLIC_KEY_ALGO_BY_CERT_ALGO[data[:algo]]
        raise AlgorithmError
      end

      data[:key_data], read = decode_public_key(raw, key_algo, offset + total_read)
      total_read += read

      trailer, read = decode_fields(raw, [
        [:serial,           :uint64],
        [:type,             :uint32],
        [:key_id,           :string],
        [:valid_principals, :string],
        [:valid_after,      :uint64],
        [:valid_before,     :uint64],
        [:critical_options, :string],
        [:extensions,       :string],
        [:reserved,         :string],
        [:signature_key,    :string],
        [:signature,        :string],
      ], offset + total_read)
      total_read += read

      [data.merge(trailer), total_read]
    end

    # Decode all of the given fields from raw.
    #
    # raw    - A binary String.
    # fields - An Array of Arrays, each containing a symbol describing the field
    #          and a Symbol describing the type of the field (:mpint, :string,
    #          :uint64, or :uint32).
    # offset - The offset into raw at which to read (default 0).
    #
    # Returns an Array containing a Hash mapping the provided field keys to the
    # decoded values and the Integer number of bytes read.
    def decode_fields(raw, fields, offset=0)
      hash = {}
      total_read = 0

      fields.each do |key, type|
        value, read = case type
        when :string
          decode_string(raw, offset + total_read)
        when :mpint
          decode_mpint(raw, offset + total_read)
        when :uint64
          decode_uint64(raw, offset + total_read)
        when :uint32
          decode_uint32(raw, offset + total_read)
        else
          raise DecodeError
        end

        hash[key] = value
        total_read += read
      end

      [hash, total_read]
    end

    # Read a string out of the provided raw data.
    #
    # raw    - A binary String.
    # offset - The offset into raw at which to read (default 0).
    #
    # Returns an Array including the decoded String and the Integer number of
    # bytes read.
    def decode_string(raw, offset=0)
      if raw.bytesize < offset + 4
        raise DecodeError, "data too short"
      end

      size_s = raw.byteslice(offset, 4)

      size = size_s.unpack("L>").first

      if raw.bytesize < offset + 4 + size
        raise DecodeError, "data too short"
      end

      string = raw.byteslice(offset + 4, size)

      [string, 4 + size]
    end

    # Encoding a string.
    #
    # string - The String to encode.
    #
    # Returns an encoded representation of the String.
    def encode_string(string)
      [string.bytesize, string].pack("L>A*")
    end

    # Read a series of strings out of the provided raw data.
    #
    # raw    - A binary String.
    # offset - The offset into raw at which to read (default 0).
    #
    # Returns an Array including the Array of decoded Strings and the Integer
    # number of bytes read.
    def decode_strings(raw, offset=0)
      total_read = 0
      strs = []

      while raw.bytesize > offset + total_read
        str, read = decode_string(raw, offset + total_read)
        strs << str
        total_read += read
      end

      [strs, total_read]
    end

    # Read the specified number of strings out of the provided raw data.
    #
    # raw    - A binary String.
    # n      - The Integer number of Strings to read.
    # offset - The offset into raw at which to read (default 0).
    #
    # Returns an Array including the Array of decoded Strings and the Integer
    # number of bytes read.
    def decode_n_strings(raw, n, offset=0)
      total_read = 0
      strs = []

      n.times do |i|
        strs[i], read = decode_string(raw, offset + total_read)
        total_read += read
      end

      [strs, total_read]
    end

    # Read a series of key/value pairs out of the provided raw data.
    #
    # raw - A binary String.
    #
    # Returns an Array including the Hash of decoded keys/values and the Integer
    # number of bytes read.
    def decode_options(raw)
      total_read = 0
      opts = {}

      while raw.bytesize > total_read
        key, read = decode_string(raw, total_read)
        total_read += read

        value_raw, read = decode_string(raw, total_read)
        total_read += read

        if value_raw.bytesize > 0
          opts[key], read = decode_string(value_raw)
          if read != value_raw.bytesize
            raise DecodeError, "bad options data"
          end
        else
          opts[key] = true
        end
      end

      [opts, total_read]
    end

    # Read a multi-precision integer from the provided raw data.
    #
    # raw    - A binary String.
    # offset - The offset into raw at which to read (default 0).
    #
    # Returns an Array including the decoded mpint as an OpenSSL::BN and the
    # Integer number of bytes read.
    def decode_mpint(raw, offset=0)
      if raw.bytesize < offset + 4
        raise DecodeError, "data too short"
      end

      str_size_s = raw.byteslice(offset, 4)
      str_size = str_size_s.unpack("L>").first
      mpi_size = str_size + 4

      if raw.bytesize < offset + mpi_size
        raise DecodeError, "data too short"
      end

      mpi_s = raw.slice(offset, mpi_size)

      # This calls OpenSSL's BN_mpi2bn() function. As far as I can tell, this
      # matches up with with MPI type defined in RFC4251 Section 5 with the
      # exception that OpenSSL doesn't enforce minimal length. We could enforce
      # this ourselves, but it doesn't seem worth the added complexity.
      mpi = OpenSSL::BN.new(mpi_s, 0)

      [mpi, mpi_size]
    end

    # Encoding a BN as an mpint.
    #
    # bn - The OpenSSL::BN to encode.
    #
    # Returns an encoded representation of the BN.
    def encode_mpint(bn)
      bn.to_s(0)
    end


    # Read a uint64 from the provided raw data.
    #
    # raw    - A binary String.
    # offset - The offset into raw at which to read (default 0).
    #
    # Returns an Array including the decoded uint64 as an Integer and the
    # Integer number of bytes read.
    def decode_uint64(raw, offset=0)
      if raw.bytesize < offset + 8
        raise DecodeError, "data too short"
      end

      uint64 = raw.byteslice(offset, 8).unpack("Q>").first

      [uint64, 8]
    end

    # Read a uint32 from the provided raw data.
    #
    # raw    - A binary String.
    # offset - The offset into raw at which to read (default 0).
    #
    # Returns an Array including the decoded uint32 as an Integer and the
    # Integer number of bytes read.
    def decode_uint32(raw, offset=0)
      if raw.bytesize < offset + 4
        raise DecodeError, "data too short"
      end

      uint32 = raw.byteslice(offset, 4).unpack("L>").first

      [uint32, 4]
    end

    extend self
  end
end
