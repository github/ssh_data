class SSHData::PublicKey::ECDSA < SSHData::PublicKey::Base
  attr_reader :curve, :public_key

  OPENSSL_CURVE_NAME_FOR_CURVE = {
    "nistp256" => "prime256v1",
    "nistp384" => "secp384r1",
    "nistp521" => "secp521r1",
  }

  def initialize(curve:, public_key:)
    @curve = curve
    @public_key = public_key
  end

  # The public key represented as an OpenSSL object.
  #
  # Returns an OpenSSL::PKey::PKey instance.
  def openssl
    @openssl ||= OpenSSL::PKey::EC.new(asn1.to_der)
  end

  private

  def asn1
    unless name = OPENSSL_CURVE_NAME_FOR_CURVE[curve]
      raise SSHData::DecodeError, "unknown curve: #{curve.inspect}"
    end

    OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::ObjectId.new("id-ecPublicKey"),
        OpenSSL::ASN1::ObjectId.new(name),
      ]),
      OpenSSL::ASN1::BitString.new(public_key),
    ])
  end
end
