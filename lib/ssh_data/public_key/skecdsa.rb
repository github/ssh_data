module SSHData
  module PublicKey
    class SKECDSA < ECDSA
      attr_reader :application

      OPENSSL_CURVE_NAME_FOR_CURVE = {
        NISTP256 => "prime256v1",
      }

      def self.check_algorithm!(algo, curve)
        unless algo == ALGO_SK_ECDSA256
          raise DecodeError, "bad algorithm: #{algo.inspect}"
        end

        unless algo == "sk-ecdsa-sha2-#{curve}@openssh.com"
          raise DecodeError, "bad curve: #{curve.inspect}"
        end
      end

      def initialize(algo:, curve:, public_key:, application:)
        @application = application
        super(algo: algo, curve: curve, public_key: public_key)
      end

      # RFC4253 binary encoding of the public key.
      #
      # Returns a binary String.
      def rfc4253
        Encoding.encode_fields(
          [:string, algo],
          [:string, curve],
          [:string, public_key_bytes],
          [:string, application],
        )
      end

      def verify(signed_data, signature)
        raise UnsupportedError, "SK-ECDSA verification is not supported."
      end

      def ==(other)
        super && other.application == application
      end
    end
  end
end
