class SSHData::PublicKey::DSA < SSHData::PublicKey::Base
  attr_reader :p, :q, :g, :y

  def initialize(p:, q:, g:, y:)
    @p = p
    @q = q
    @g = g
    @y = y
  end

  # The public key represented as an OpenSSL object.
  #
  # Returns an OpenSSL::PKey::PKey instance.
  def openssl
    @openssl ||= OpenSSL::PKey::DSA.new(asn1.to_der)
  end

  private

  def asn1
    OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::ObjectId.new("DSA"),
        OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::Integer.new(p),
          OpenSSL::ASN1::Integer.new(q),
          OpenSSL::ASN1::Integer.new(g),
        ]),
      ]),
      OpenSSL::ASN1::BitString.new(OpenSSL::ASN1::Integer.new(y).to_der),
    ])
  end
end
