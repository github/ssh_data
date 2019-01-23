class SSHData::PublicKey::RSA < SSHData::PublicKey::Base
  attr_reader :e, :n

  def initialize(e:, n:)
    @e = e
    @n = n
  end

  # The public key represented as an OpenSSL object.
  #
  # Returns an OpenSSL::PKey::PKey instance.
  def openssl
    @openssl ||= OpenSSL::PKey::RSA.new(asn1.to_der)
  end

  def verify(signed_data, signature)
    sig_algo, raw_sig, _ = SSHData::Encoding.decode_signature(signature)
    if sig_algo != SSHData::PublicKey::ALGO_RSA
      raise SSHData::DecodeError, "bad signature algorithm: #{sig_algo.inspect}"
    end

    openssl.verify(OpenSSL::Digest::SHA1.new, raw_sig, signed_data)
  end

  private

  def asn1
    OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::ObjectId.new("rsaEncryption"),
        OpenSSL::ASN1::Null.new(nil),
      ]),
      OpenSSL::ASN1::BitString.new(OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::Integer.new(n),
        OpenSSL::ASN1::Integer.new(e),
      ]).to_der),
    ])
  end
end
