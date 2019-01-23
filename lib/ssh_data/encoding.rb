module SSHData::Encoding
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
    SSHData::Certificate::ALGO_RSA      => SSHData::PublicKey::ALGO_RSA,
    SSHData::Certificate::ALGO_DSA      => SSHData::PublicKey::ALGO_DSA,
    SSHData::Certificate::ALGO_ECDSA256 => SSHData::PublicKey::ALGO_ECDSA256,
    SSHData::Certificate::ALGO_ECDSA384 => SSHData::PublicKey::ALGO_ECDSA384,
    SSHData::Certificate::ALGO_ECDSA521 => SSHData::PublicKey::ALGO_ECDSA521,
    SSHData::Certificate::ALGO_ED25519  => SSHData::PublicKey::ALGO_ED25519,
  }

  KEY_FIELDS_BY_PUBLIC_KEY_ALGO = {
    SSHData::PublicKey::ALGO_RSA      => RSA_KEY_FIELDS,
    SSHData::PublicKey::ALGO_DSA      => DSA_KEY_FIELDS,
    SSHData::PublicKey::ALGO_ECDSA256 => ECDSA_KEY_FIELDS,
    SSHData::PublicKey::ALGO_ECDSA384 => ECDSA_KEY_FIELDS,
    SSHData::PublicKey::ALGO_ECDSA521 => ECDSA_KEY_FIELDS,
    SSHData::PublicKey::ALGO_ED25519  => ED25519_KEY_FIELDS,
  }

  # Decode the signature.
  #
  # raw    - The binary String signature as described by RFC4253 section 6.6.
  # offset - Integer number of bytes into `raw` at which we should start
  #          reading.
  #
  # Returns an Array containing the decoded algorithm String, the decoded binary
  # signature String, and the Integer number of bytes read.
  def self.decode_signature(raw, offset=0)
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
  def self.decode_public_key(raw, algo=nil, offset=0)
    total_read = 0

    if algo.nil?
      algo, read = decode_string(raw, offset + total_read)
      total_read += read
    end

    unless fields = KEY_FIELDS_BY_PUBLIC_KEY_ALGO[algo]
      raise SSHData::DecodeError, "unknown key algo: #{algo.inspect}"
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
  def self.decode_certificate(raw, offset=0)
    total_read = 0

    data, read = decode_fields(raw, [
      [:algo,  :string],
      [:nonce, :string],
    ], offset + total_read)
    total_read += read

    unless key_algo = PUBLIC_KEY_ALGO_BY_CERT_ALGO[data[:algo]]
      raise SSHData::DecodeError, "unknown cert algo: #{data[:algo].inspect}"
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

  # Decode all of the given fields from data.
  #
  # data   - A binary String.
  # fields - An Array of Arrays, each containing a symbol describing the field
  #          and a Symbol describing the type of the field (:mpint, :string,
  #          :uint64, or :uint32).
  # offset - The offset into data at which to read (default 0).
  #
  # Returns an Array containing a Hash mapping the provided field keys to the
  # decoded values and the Integer number of bytes read.
  def decode_fields(data, fields, offset=0)
    hash = {}
    total_read = 0

    fields.each do |key, type|
      value, read = case type
      when :string
        decode_string(data, offset + total_read)
      when :mpint
        decode_mpint(data, offset + total_read)
      when :uint64
        decode_uint64(data, offset + total_read)
      when :uint32
        decode_uint32(data, offset + total_read)
      else
        raise SSHData::DecodeError
      end

      hash[key] = value
      total_read += read
    end

    [hash, total_read]
  end

  # Read a string out of the provided data.
  #
  # data   - A binary String.
  # offset - The offset into data at which to read (default 0).
  #
  # Returns an Array including the decoded String and the Integer number of
  # bytes read.
  def decode_string(data, offset=0)
    if data.bytesize < offset + 4
      raise SSHData::DecodeError, "data too short"
    end

    size_s = data.byteslice(offset, 4)

    size = size_s.unpack("L>").first

    if data.bytesize < offset + 4 + size
      raise SSHData::DecodeError, "data too short"
    end

    string = data.byteslice(offset + 4, size)

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

  # Read a multi-precision integer from the provided data.
  #
  # data   - A binary String.
  # offset - The offset into data at which to read (default 0).
  #
  # Returns an Array including the decoded mpint as an OpenSSL::BN and the
  # Integer number of bytes read.
  def decode_mpint(data, offset=0)
    if data.bytesize < offset + 4
      raise SSHData::DecodeError, "data too short"
    end

    str_size_s = data.byteslice(offset, 4)
    str_size = str_size_s.unpack("L>").first
    mpi_size = str_size + 4

    if data.bytesize < offset + mpi_size
      raise SSHData::DecodeError, "data too short"
    end

    mpi_s = data.slice(offset, mpi_size)

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


  # Read a uint64 from the provided data.
  #
  # data   - A binary String.
  # offset - The offset into data at which to read (default 0).
  #
  # Returns an Array including the decoded uint64 as an Integer and the
  # Integer number of bytes read.
  def decode_uint64(data, offset=0)
    if data.bytesize < offset + 8
      raise SSHData::DecodeError, "data too short"
    end

    uint64 = data.byteslice(offset, 8).unpack("Q>").first

    [uint64, 8]
  end

  # Read a uint32 from the provided data.
  #
  # data   - A binary String.
  # offset - The offset into data at which to read (default 0).
  #
  # Returns an Array including the decoded uint32 as an Integer and the
  # Integer number of bytes read.
  def decode_uint32(data, offset=0)
    if data.bytesize < offset + 4
      raise SSHData::DecodeError, "data too short"
    end

    uint32 = data.byteslice(offset, 4).unpack("L>").first

    [uint32, 4]
  end

  extend self
end
