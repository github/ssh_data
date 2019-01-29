module SSHData
  module PrivateKey
    class DSA < Base
      attr_reader :p, :q, :g, :x, :y

      def initialize(algo:, p:, q:, g:, x:, y:, comment:)
        unless algo == PublicKey::ALGO_DSA
          raise DecodeError, "bad algorithm: #{algo.inspect}"
        end

        @p = p
        @q = q
        @g = g
        @x = x
        @y = y

        super(algo: algo, comment: comment)
      end

      def public_key
        PublicKey::DSA.new(algo: algo, p: p, q: q, g: g, y: y)
      end

      def openssl
        OpenSSL::PKey::DSA.new(asn1.to_der)
      end

      private

      def asn1
        OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(0)),
          OpenSSL::ASN1::Integer.new(p),
          OpenSSL::ASN1::Integer.new(q),
          OpenSSL::ASN1::Integer.new(g),
          OpenSSL::ASN1::Integer.new(y),
          OpenSSL::ASN1::Integer.new(x),
        ])
      end
    end
  end
end
