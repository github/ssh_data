module SSHData
  module PublicKey
    class SKED25519 < ED25519
      attr_reader :application

      def initialize(algo:, pk:, application:)
        @application = application
        super(algo: algo, pk: pk)
      end

      def self.algorithm_identifier
        ALGO_SKED25519
      end

      # RFC4253 binary encoding of the public key.
      #
      # Returns a binary String.
      def rfc4253
        Encoding.encode_fields(
          [:string, algo],
          [:string, pk],
          [:string, application],
        )
      end

      def verify(signed_data, signature)
        self.class.ed25519_gem_required!

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

        if sig_algo != self.class.algorithm_identifier
          raise DecodeError, "bad signature algorithm: #{sig_algo.inspect}"
        end

        application_hash = OpenSSL::Digest::SHA256.digest(application)
        message_hash = OpenSSL::Digest::SHA256.digest(signed_data)

        blob =
          application_hash +
          Encoding.encode_uint8(sk_flags) +
          Encoding.encode_uint32(counter) +
          message_hash

        begin
          ed25519_key.verify(raw_sig, blob)
        rescue Ed25519::VerifyError
          false
        end
      end

      def ==(other)
        super && other.application == application
      end
    end
  end
end
