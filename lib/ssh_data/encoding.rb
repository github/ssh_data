module SSHData
  module Encoding
    # Fields in an OpenSSL private key
    # https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
    OPENSSH_PRIVATE_KEY_MAGIC = "openssh-key-v1\x00"

    OPENSSH_SIGNATURE_MAGIC = "SSHSIG"
    OPENSSH_SIGNATURE_VERSION = 0x01

    OPENSSH_SIGNATURE_FIELDS = [
      [:sigversion,     :uint32],
      [:publickey,      :string],
      [:namespace,      :string],
      [:reserved,       :string],
      [:hash_algorithm, :string],
      [:signature,      :string],
    ]

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

    # Fields in a DSA private key
    DSA_PRIVATE_KEY_FIELDS = [
      [:p, :mpint],
      [:q, :mpint],
      [:g, :mpint],
      [:y, :mpint],
      [:x, :mpint]
    ]

    # Fields in a ECDSA private key
    ECDSA_PRIVATE_KEY_FIELDS = [
      [:curve,       :string],
      [:public_key,  :string],
      [:private_key, :mpint],
    ]

    # Fields in a ED25519 private key
    ED25519_PRIVATE_KEY_FIELDS = [
      [:pk, :string],
      [:sk, :string]
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

    # Fields in an SK-ECDSA public key
    SKECDSA_KEY_FIELDS = [
      [:curve,      :string],
      [:public_key, :string],
      [:application, :string]
    ]

    # Fields in a ED25519 public key
    ED25519_KEY_FIELDS = [
      [:pk, :string]
    ]

    # Fields in a SK-ED25519 public key
    SKED25519_KEY_FIELDS = [
      [:pk, :string],
      [:application, :string]
    ]

    PUBLIC_KEY_ALGO_BY_CERT_ALGO = {
      Certificate::ALGO_RSA        => PublicKey::ALGO_RSA,
      Certificate::ALGO_DSA        => PublicKey::ALGO_DSA,
      Certificate::ALGO_ECDSA256   => PublicKey::ALGO_ECDSA256,
      Certificate::ALGO_ECDSA384   => PublicKey::ALGO_ECDSA384,
      Certificate::ALGO_ECDSA521   => PublicKey::ALGO_ECDSA521,
      Certificate::ALGO_ED25519    => PublicKey::ALGO_ED25519,
      Certificate::ALGO_SKECDSA256 => PublicKey::ALGO_SKECDSA256,
      Certificate::ALGO_SKED25519  => PublicKey::ALGO_SKED25519,
    }

    CERT_ALGO_BY_PUBLIC_KEY_ALGO = {
      PublicKey::ALGO_RSA        => Certificate::ALGO_RSA,
      PublicKey::ALGO_DSA        => Certificate::ALGO_DSA,
      PublicKey::ALGO_ECDSA256   => Certificate::ALGO_ECDSA256,
      PublicKey::ALGO_ECDSA384   => Certificate::ALGO_ECDSA384,
      PublicKey::ALGO_ECDSA521   => Certificate::ALGO_ECDSA521,
      PublicKey::ALGO_ED25519    => Certificate::ALGO_ED25519,
      PublicKey::ALGO_SKECDSA256 => Certificate::ALGO_SKECDSA256,
      PublicKey::ALGO_SKED25519  => Certificate::ALGO_SKED25519,
    }

    KEY_FIELDS_BY_PUBLIC_KEY_ALGO = {
      PublicKey::ALGO_RSA      => RSA_KEY_FIELDS,
      PublicKey::ALGO_DSA      => DSA_KEY_FIELDS,
      PublicKey::ALGO_ECDSA256 => ECDSA_KEY_FIELDS,
      PublicKey::ALGO_ECDSA384 => ECDSA_KEY_FIELDS,
      PublicKey::ALGO_ECDSA521 => ECDSA_KEY_FIELDS,
      PublicKey::ALGO_ED25519  => ED25519_KEY_FIELDS,
      PublicKey::ALGO_SKED25519 => SKED25519_KEY_FIELDS,
      PublicKey::ALGO_SKECDSA256 => SKECDSA_KEY_FIELDS,
    }

    KEY_FIELDS_BY_PRIVATE_KEY_ALGO = {
      PublicKey::ALGO_RSA      => RSA_PRIVATE_KEY_FIELDS,
      PublicKey::ALGO_DSA      => DSA_PRIVATE_KEY_FIELDS,
      PublicKey::ALGO_ECDSA256 => ECDSA_PRIVATE_KEY_FIELDS,
      PublicKey::ALGO_ECDSA384 => ECDSA_PRIVATE_KEY_FIELDS,
      PublicKey::ALGO_ECDSA521 => ECDSA_PRIVATE_KEY_FIELDS,
      PublicKey::ALGO_ED25519  => ED25519_PRIVATE_KEY_FIELDS,
    }

    # Get the type from a PEM encoded blob.
    #
    # pem - A PEM encoded String.
    #
    # Returns a String PEM type.
    def pem_type(pem)
      head = pem.split("\n", 2).first.strip

      head_prefix = "-----BEGIN "
      head_suffix = "-----"

      unless head.start_with?(head_prefix) && head.end_with?(head_suffix)
        raise DecodeError, "bad PEM encoding"
      end

      type_size = head.bytesize - head_prefix.bytesize - head_suffix.bytesize

      head.byteslice(head_prefix.bytesize, type_size)
    end

    # Get the raw data from a PEM encoded blob.
    #
    # pem  - The PEM encoded String to decode.
    # type - The String PEM type we're expecting.
    #
    # Returns the decoded String.
    def decode_pem(pem, type)
      lines = pem.split("\n").map(&:strip)

      unless lines.shift == "-----BEGIN #{type}-----"
        raise DecodeError, "bad PEM header"
      end

      unless lines.pop == "-----END #{type}-----"
        raise DecodeError, "bad PEM footer"
      end

      begin
        Base64.strict_decode64(lines.join)
      rescue ArgumentError
        raise DecodeError, "bad PEM data"
      end
    end

    # Decode an OpenSSH private key.
    #
    # raw - The binary String private key.
    #
    # Returns an Array containing a Hash describing the private key and the
    # Integer number of bytes read.
    def decode_openssh_private_key(raw)
      total_read = 0

      magic = raw.byteslice(total_read, OPENSSH_PRIVATE_KEY_MAGIC.bytesize)
      unless magic == OPENSSH_PRIVATE_KEY_MAGIC
        raise DecodeError, "bad OpenSSH private key"
      end
      total_read += OPENSSH_PRIVATE_KEY_MAGIC.bytesize

      data, read = decode_fields(raw, OPENSSH_PRIVATE_KEY_FIELDS, total_read)
      total_read += read

      # TODO: add support for encrypted private keys
      unless data[:ciphername] == "none" && data[:kdfname] == "none"
        raise DecryptError, "cannot decode encrypted private keys"
      end

      data[:public_keys], read = decode_n_strings(raw, total_read, data[:nkeys])
      total_read += read

      privs, read = decode_string(raw, total_read)
      total_read += read

      privs_read = 0

      data[:checkint1], read = decode_uint32(privs, privs_read)
      privs_read += read

      data[:checkint2], read = decode_uint32(privs, privs_read)
      privs_read += read

      unless data[:checkint1] == data[:checkint2]
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
      data[:padding] = privs.byteslice(privs_read..-1)
      unless data[:padding].bytes.each_with_index.all? { |b, i| b == (i + 1) % 255 }
        raise DecodeError, "bad padding: #{data[:padding].inspect}"
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
    def decode_public_key(raw, offset=0, algo=nil)
      total_read = 0

      if algo.nil?
        algo, read = decode_string(raw, offset + total_read)
        total_read += read
      end

      unless fields = KEY_FIELDS_BY_PUBLIC_KEY_ALGO[algo]
        raise AlgorithmError, "unknown algorithm: #{algo.inspect}"
      end

      data, read = decode_fields(raw, fields, offset + total_read)
      total_read += read

      data[:algo] = algo

      [data, total_read]
    end

    # Decode the fields in a public key encoded as an SSH string.
    #
    # raw    - Binary public key as described by RFC4253 section 6.6 wrapped in
    #          an SSH string..
    # algo   - String public key algorithm identifier (optional).
    # offset - Integer number of bytes into `raw` at which we should start
    #          reading.
    #
    # Returns an Array containing a Hash describing the public key and the
    # Integer number of bytes read.
    def decode_string_public_key(raw, offset=0, algo=nil)
      key_raw, str_read = decode_string(raw, offset)
      key, cert_read = decode_public_key(key_raw, 0, algo)

      if cert_read != key_raw.bytesize
        raise DecodeError, "unexpected trailing data"
      end

      [key, str_read]
    end

    def decode_openssh_signature(raw, offset=0)
      total_read = 0

      magic = raw.byteslice(offset, OPENSSH_SIGNATURE_MAGIC.bytesize)
      unless magic == OPENSSH_SIGNATURE_MAGIC
        raise DecodeError, "bad OpenSSH signature"
      end

      total_read += OPENSSH_SIGNATURE_MAGIC.bytesize
      offset += total_read
      data, read = decode_fields(raw, OPENSSH_SIGNATURE_FIELDS, offset)
      total_read += read
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

      algo, read = decode_string(raw, offset + total_read)
      total_read += read

      unless key_algo = PUBLIC_KEY_ALGO_BY_CERT_ALGO[algo]
        raise AlgorithmError, "unknown algorithm: #{algo.inspect}"
      end

      data, read = decode_fields(raw, [
        [:nonce,            :string],
        [:public_key,       :public_key, key_algo],
        [:serial,           :uint64],
        [:type,             :uint32],
        [:key_id,           :string],
        [:valid_principals, :list],
        [:valid_after,      :time],
        [:valid_before,     :time],
        [:critical_options, :options],
        [:extensions,       :options],
        [:reserved,         :string],
        [:signature_key,    :string_public_key],
        [:signature,        :string],
      ], offset + total_read)
      total_read += read

      data[:algo] = algo

      [data, total_read]
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

      fields.each do |key, type, *args|
        hash[key], read = case type
        when :string
          decode_string(raw, offset + total_read, *args)
        when :list
          decode_list(raw, offset + total_read, *args)
        when :mpint
          decode_mpint(raw, offset + total_read, *args)
        when :time
          decode_time(raw, offset + total_read, *args)
        when :uint64
          decode_uint64(raw, offset + total_read, *args)
        when :uint32
          decode_uint32(raw, offset + total_read, *args)
        when :public_key
          decode_public_key(raw, offset + total_read, *args)
        when :string_public_key
          decode_string_public_key(raw, offset + total_read, *args)
        when :options
          decode_options(raw, offset + total_read, *args)
        else
          raise DecodeError
        end
        total_read += read
      end

      [hash, total_read]
    end

    # Encode the series of fields into a binary string.
    #
    # fields - A series of Arrays, each containing a Symbol type and a value to
    #          encode.
    #
    # Returns a binary String.
    def encode_fields(*fields)
      fields.map do |type, value|
        case type
        when :raw
          value
        when :string
          encode_string(value)
        when :list
          encode_list(value)
        when :mpint
          encode_mpint(value)
        when :time
          encode_time(value)
        when :uint64
          encode_uint64(value)
        when :uint32
          encode_uint32(value)
        when :options
          encode_options(value)
        else
          raise DecodeError, "bad type: #{type}"
        end
      end.join
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
    # value - The String value to encode.
    #
    # Returns an encoded representation of the String.
    def encode_string(value)
      [value.bytesize, value].pack("L>A*")
    end

    # Read a series of strings out of the provided raw data.
    #
    # raw    - A binary String.
    # offset - The offset into raw at which to read (default 0).
    #
    # Returns an Array including the Array of decoded Strings and the Integer
    # number of bytes read.
    def decode_list(raw, offset=0)
      list_raw, str_read = decode_string(raw, offset)

      list_read = 0
      list = []

      while list_raw.bytesize > list_read
        value, read = decode_string(list_raw, list_read)
        list << value
        list_read += read
      end

      if list_read != list_raw.bytesize
        raise DecodeError, "bad strings list"
      end

      [list, str_read]
    end

    # Encode a list of strings.
    #
    # value - The Array of Strings to encode.
    #
    # Returns an encoded representation of the list.
    def encode_list(value)
      encode_string(value.map { |s| encode_string(s) }.join)
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

    # Encode a BN as an mpint.
    #
    # value - The OpenSSL::BN value to encode.
    #
    # Returns an encoded representation of the BN.
    def encode_mpint(value)
      value.to_s(0)
    end

    # Read a time from the provided raw data.
    #
    # raw    - A binary String.
    # offset - The offset into raw at which to read (default 0).
    #
    # Returns an Array including the decoded Time and the Integer number of
    # bytes read.
    def decode_time(raw, offset=0)
      time_raw, read = decode_uint64(raw, offset)
      [Time.at(time_raw), read]
    end

    # Encode a time.
    #
    # value - The Time value to encode.
    #
    # Returns an encoded representation of the Time.
    def encode_time(value)
      encode_uint64(value.to_i)
    end

    # Read the specified number of strings out of the provided raw data.
    #
    # raw    - A binary String.
    # offset - The offset into raw at which to read (default 0).
    # n      - The Integer number of Strings to read.
    #
    # Returns an Array including the Array of decoded Strings and the Integer
    # number of bytes read.
    def decode_n_strings(raw, offset=0, n)
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
    # raw    - A binary String.
    # offset - The offset into raw at which to read (default 0).
    #
    # Returns an Array including the Hash of decoded keys/values and the Integer
    # number of bytes read.
    def decode_options(raw, offset=0)
      opts_raw, str_read = decode_string(raw, offset)

      opts_read = 0
      opts = {}

      while opts_raw.bytesize > opts_read
        key, read = decode_string(opts_raw, opts_read)
        opts_read += read

        value_raw, read = decode_string(opts_raw, opts_read)
        opts_read += read

        if value_raw.bytesize > 0
          opts[key], read = decode_string(value_raw)
          if read != value_raw.bytesize
            raise DecodeError, "bad options data"
          end
        else
          opts[key] = true
        end
      end

      if opts_read != opts_raw.bytesize
        raise DecodeError, "bad options"
      end

      [opts, str_read]
    end

    # Encode series of key/value pairs.
    #
    # value - The Hash value to encode.
    #
    # Returns an encoded representation of the Hash.
    def encode_options(value)
      opts_raw = value.reduce("") do |encoded, (key, value)|
        value_str = value == true ? "" : encode_string(value)
        encoded + encode_string(key) + encode_string(value_str)
      end

      encode_string(opts_raw)
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

    # Encoding an integer as a uint64.
    #
    # value - The Integer value to encode.
    #
    # Returns an encoded representation of the value.
    def encode_uint64(value)
      [value].pack("Q>")
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

    # Encoding an integer as a uint32.
    #
    # value - The Integer value to encode.
    #
    # Returns an encoded representation of the value.
    def encode_uint32(value)
      [value].pack("L>")
    end

    # Read a uint8 from the provided raw data.
    #
    # raw    - A binary String.
    # offset - The offset into raw at which to read (default 0).
    #
    # Returns an Array including the decoded uint8 as an Integer and the
    # Integer number of bytes read.
    def decode_uint8(raw, offset=0)
      if raw.bytesize < offset + 1
        raise DecodeError, "data too short"
      end

      uint8 = raw.byteslice(offset, 1).unpack("C").first

      [uint8, 1]
    end

    # Encoding an integer as a uint8.
    #
    # value - The Integer value to encode.
    #
    # Returns an encoded representation of the value.
    def encode_uint8(value)
      [value].pack("C")
    end

    extend self
  end
end
