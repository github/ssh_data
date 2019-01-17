require "openssl"
require "base64"

class SSHData
  module Encoding
    # Decode a certificate.
    #
    # cert - An SSH formatted certificate.
    #
    # Returns a Hash representing the decoded fields from the certificate.
    def decode_cert(cert)
      _, cert_b64, _ = cert.split(" ")
      if cert_b64.nil?
        raise DecodeError
      end

      cert_raw = Base64.decode64(cert_b64)
      type, _ = read_string(cert_raw)

      hash, total_read = case type
      when SSHData::RSA_CERT_TYPE
        decode_all(cert_raw, [
          [:key_type,         :string],
          [:nonce,            :string],
          [:e,                :mpint],
          [:n,                :mpint],
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
        ])
      when SSHData::DSA_CERT_TYPE
        decode_all(cert_raw, [
          [:key_type,         :string],
          [:nonce,            :string],
          [:p,                :mpint],
          [:q,                :mpint],
          [:g,                :mpint],
          [:y,                :mpint],
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
        ])
      when *SSHData::ECDSA_CERT_TYPES
        decode_all(cert_raw, [
          [:key_type,         :string],
          [:nonce,            :string],
          [:curve,            :string],
          [:public_key,       :string],
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
        ])
      when SSHData::ED25519_CERT_TYPE
        decode_all(cert_raw, [
          [:key_type,         :string],
          [:nonce,            :string],
          [:pk,               :string],
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
        ])
      else
        raise DecodeError, "unknown cert type: #{type}"
      end

      # the signature is over all data up to the signature field.
      hash[:signed_data] = cert_raw.byteslice(0, total_read)

      hash[:signature], read = read_string(cert_raw, total_read)
      total_read += read

      if cert_raw.bytesize != total_read
        raise DecodeError, "bad data length"
      end

      hash
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
end
