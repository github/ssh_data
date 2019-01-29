module SSHData
  module PrivateKey
    class ECDSA < Base
      attr_reader :curve, :public_key_bytes, :private_key_bytes, :public_key, :openssl

      def initialize(algo:, curve:, public_key:, private_key:, comment:)
        unless [PublicKey::ALGO_ECDSA256, PublicKey::ALGO_ECDSA384, PublicKey::ALGO_ECDSA521].include?(algo)
          raise DecodeError, "bad algorithm: #{algo.inspect}"
        end

        unless algo == "ecdsa-sha2-#{curve}"
          raise DecodeError, "bad curve: #{curve.inspect}"
        end

        @curve = curve
        @public_key_bytes = public_key
        @private_key_bytes = private_key

        super(algo: algo, comment: comment)

        @openssl = begin
          OpenSSL::PKey::EC.new(asn1.to_der)
        rescue ArgumentError
          raise DecodeError, "bad key data"
        end

        @public_key = PublicKey::ECDSA.new(
          algo: algo,
          curve: curve,
          public_key: public_key_bytes
        )
      end

      private

      def asn1
        unless name = PublicKey::ECDSA::OPENSSL_CURVE_NAME_FOR_CURVE[curve]
          raise DecodeError, "unknown curve: #{curve.inspect}"
        end

        OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::Integer.new(1),
          OpenSSL::ASN1::OctetString.new(private_key_bytes.to_s(2)),
          OpenSSL::ASN1::ObjectId.new(name, 0, :EXPLICIT, :CONTEXT_SPECIFIC),
          OpenSSL::ASN1::BitString.new(public_key_bytes, 1, :EXPLICIT, :CONTEXT_SPECIFIC)
        ])
      end
    end
  end
end
