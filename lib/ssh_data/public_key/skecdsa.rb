module SSHData
  module PublicKey
    class SKECDSA < ECDSA
      include SecurityKey
      attr_reader :application

      OPENSSL_CURVE_NAME_FOR_CURVE = {
        NISTP256 => "prime256v1",
      }

      def self.check_algorithm!(algo, curve)
        unless algo == ALGO_SKECDSA256
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

      def verify(signed_data, signature, **opts)
        opts = DEFAULT_SK_VERIFY_OPTS.merge(opts)

        read = 0
        sig_algo, raw_sig, sk_flags, blob = build_signing_blob(application, signed_data, signature)
        self.class.check_algorithm!(sig_algo, curve)

        openssl_sig = self.class.openssl_signature(raw_sig)
        digest = DIGEST_FOR_CURVE[curve]

        result = openssl.verify(digest.new, openssl_sig, blob)

        if opts[:user_presence_required] && (sk_flags & SK_FLAG_USER_PRESENCE != SK_FLAG_USER_PRESENCE)
          false
        elsif opts[:user_verification_required] && (sk_flags & SK_FLAG_USER_VERIFICATION != SK_FLAG_USER_VERIFICATION)
          false
        else
          result
        end
      end

      def ==(other)
        super && other.application == application
      end
    end
  end
end
