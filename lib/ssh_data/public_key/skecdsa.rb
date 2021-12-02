module SSHData
  module PublicKey
    class SKECDSA < ECDSA
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

      def verify(signed_data, signature)
        read = 0
        sig_algo, raw_sig, signature_read = Encoding.decode_signature(signature)
        read += signature_read
        sk_flags, sk_flags_read = Encoding.decode_uint8(signature, read)
        read += sk_flags_read
        counter, counter_read = Encoding.decode_uint32(signature, read)
        read += counter_read

        if read != signature.bytesize
          raise DecodeError, "unexpected trailing data"
        end

        self.class.check_algorithm!(sig_algo, curve)

        application_hash = OpenSSL::Digest::SHA256.digest(application)
        message_hash = OpenSSL::Digest::SHA256.digest(signed_data)

        blob =
          application_hash +
          Encoding.encode_uint8(sk_flags) +
          Encoding.encode_uint32(counter) +
          message_hash

        openssl_sig = self.class.openssl_signature(raw_sig)
        digest = DIGEST_FOR_CURVE[curve]

        openssl.verify(digest.new, openssl_sig, blob)
      end

      def ==(other)
        super && other.application == application
      end
    end
  end
end
