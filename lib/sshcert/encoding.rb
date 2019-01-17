require "openssl"
require "base64"

class SSHCert
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

      case type
      when SSHCert::RSA_CERT_TYPE
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
          [:signature,        :string],
        ])
      when SSHCert::DSA_CERT_TYPE
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
          [:signature,        :string],
        ])
      when *SSHCert::ECDSA_CERT_TYPES
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
          [:signature,        :string],
        ])
      when SSHCert::ED25519_CERT_TYPE
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
          [:signature,        :string],
        ])
      else
        raise DecodeError, "unknown cert type: #{type}"
      end
    end

    # Decode all of the given fields from data.
    #
    # data   - A binary String.
    # fields - An Array of Arrays, each containing a symbol describing the field
    #          and a Symbol describing the type of the field (:mpint, :string,
    #          :uint64, or :uint32).
    #
    # Returns a Hash mapping the provide field keys to the decoded values.
    def decode_all(data, fields)
      fields.each_with_object({}) do |(key, type), result|
        case type
        when :string
          string, data = read_string(data)
          result[key] = string
        when :mpint
          mpint, data = read_mpint(data)
          result[key] = mpint
        when :uint64
          uint64, data = read_uint64(data)
          result[key] = uint64
        when :uint32
          uint32, data = read_uint32(data)
          result[key] = uint32
        else
          raise SSHCert::DecodeError
        end
      end
    end

    # Read a string out of the provided data.
    #
    # data - A binary String.
    #
    # Returns an Array including the decoded String and the remaining binary
    # String data.
    def read_string(data)
      if data.bytesize < 4
        raise SSHCert::DecodeError, "data too short"
      end

      size_s, data = data.byteslice(0...4), data.byteslice(4..-1)
      size = size_s.unpack("L>").first

      if data.bytesize < size
        raise SSHCert::DecodeError, "data too short"
      end

      [data.byteslice(0...size), data.byteslice(size..-1)]
    end

    # Read a multi-precision integer from the provided data.
    #
    # data - A binary String.
    #
    # Returns an Array including the decoded mpint as an OpenSSL::BN and the
    # remaining binary String data.
    def read_mpint(data)
      if data.bytesize < 4
        raise SSHCert::DecodeError, "data too short"
      end

      str_size_s = data.byteslice(0...4)
      str_size = str_size_s.unpack("N").first
      mpi_size = str_size + 4

      if data.bytesize < mpi_size
        raise SSHCert::DecodeError, "data too short"
      end

      mpi_s, data = data.slice(0...mpi_size), data.slice(mpi_size..-1)

      # This calls OpenSSL's BN_mpi2bn() function. As far as I can tell, this
      # matches up with with MPI type defined in RFC4251 Section 5 with the
      # exception that OpenSSL doesn't enforce minimal length. We could enforce
      # this ourselves, but it doesn't seem worth the added complexity.
      mpi = OpenSSL::BN.new(mpi_s, 0)

      [mpi, data]
    end

    # Read a uint64 from the provided data.
    #
    # data - A binary String.
    #
    # Returns an Array including the decoded uint64 as an Integer and the
    # remaining binary String data.
    def read_uint64(data)
      if data.bytesize < 8
        raise SSHCert::DecodeError, "data too short"
      end

      data.unpack("Q>a*")
    end

    # Read a uint32 from the provided data.
    #
    # data - A binary String.
    #
    # Returns an Array including the decoded uint32 as an Integer and the
    # remaining binary String data.
    def read_uint32(data)
      if data.bytesize < 4
        raise SSHCert::DecodeError, "data too short"
      end

      data.unpack("L>a*")
    end

    extend self
  end
end
