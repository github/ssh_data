require "openssl"
require "base64"

module SSHData::Encoding
  # Certificate fields that come before the public key.
  CERT_HEADER_FIELDS = [
    [:type_string, :string],
    [:nonce,       :string],
  ]

  # Certificate fields that come after the public key.
  CERT_TRAILER_FIELDS = [
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
  ]

  # The fields describing the public key for each type of certificate.
  KEY_FIELDS_BY_CERT_TYPE = {
    SSHData::Certificate::RSA_CERT_TYPE => [
      [:e, :mpint],
      [:n, :mpint]
    ],
    SSHData::Certificate::DSA_CERT_TYPE => [
      [:p, :mpint],
      [:q, :mpint],
      [:g, :mpint],
      [:y, :mpint]
    ],
    SSHData::Certificate::ECDSA_SHA2_NISTP256_CERT_TYPE => [
      [:curve,      :string],
      [:public_key, :string]
    ],
    SSHData::Certificate::ECDSA_SHA2_NISTP384_CERT_TYPE => [
      [:curve,      :string],
      [:public_key, :string]
    ],
    SSHData::Certificate::ECDSA_SHA2_NISTP521_CERT_TYPE => [
      [:curve,      :string],
      [:public_key, :string]
    ],
    SSHData::Certificate::ED25519_CERT_TYPE => [
      [:pk, :string]
    ]
  }

  # Decode the fields in a certificate.
  #
  # cert - An SSH formatted certificate, including key type, encoded key and
  #        optional user/host names.
  #
  # Returns a Hash of the certificate's fields.
  def self.parse_certificate(cert)
    type, cert_b64, _ = cert.split(" ")
    if cert_b64.nil?
      raise SSHData::DecodeError
    elsif !KEY_FIELDS_BY_CERT_TYPE.key?(type)
      raise SSHData::DecodeError, "unknown certificate type: #{type.inspect}"
    end

    cert_raw = Base64.decode64(cert_b64)
    offset = 0
    data = {}

    header_data, read = decode_all(cert_raw, CERT_HEADER_FIELDS, 0)
    offset += read
    data.merge!(header_data)

    if type != data[:type_string]
      raise SSHData::DecodeError, "type mismatch: #{type.inspect}!=#{data[:type_string].inspect}"
    end

    key_fields = KEY_FIELDS_BY_CERT_TYPE[type]
    data[:key_data], read = decode_all(cert_raw, key_fields, offset)
    offset += read

    trailer_data, read = decode_all(cert_raw, CERT_TRAILER_FIELDS, offset)
    offset += read
    data.merge!(trailer_data)

    # The signature is over all data up to the signature field. This isn't its
    # own field, but we parse it out here so we don't have to do it later.
    data[:signed_data] = cert_raw.byteslice(0, read)
    data[:signature], read = read_string(cert_raw, offset)
    offset += read

    if cert_raw.bytesize != offset
      raise SSHData::DecodeError, "bad data length"
    end

    data
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
  def decode_all(data, fields, offset=0)
    hash = {}
    total_read = 0

    fields.each do |key, type|
      value, read = case type
      when :string
        read_string(data, offset + total_read)
      when :mpint
        read_mpint(data, offset + total_read)
      when :uint64
        read_uint64(data, offset + total_read)
      when :uint32
        read_uint32(data, offset + total_read)
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
  def read_string(data, offset=0)
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

  # Read a multi-precision integer from the provided data.
  #
  # data   - A binary String.
  # offset - The offset into data at which to read (default 0).
  #
  # Returns an Array including the decoded mpint as an OpenSSL::BN and the
  # Integer number of bytes read.
  def read_mpint(data, offset=0)
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

  # Read a uint64 from the provided data.
  #
  # data   - A binary String.
  # offset - The offset into data at which to read (default 0).
  #
  # Returns an Array including the decoded uint64 as an Integer and the
  # Integer number of bytes read.
  def read_uint64(data, offset=0)
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
  def read_uint32(data, offset=0)
    if data.bytesize < offset + 4
      raise SSHData::DecodeError, "data too short"
    end

    uint32 = data.byteslice(offset, 4).unpack("L>").first

    [uint32, 4]
  end

  extend self
end
