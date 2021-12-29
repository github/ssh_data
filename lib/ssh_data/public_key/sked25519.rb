module SSHData
  module PublicKey
    class SKED25519 < ED25519
      include SecurityKey
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

      def verify(signed_data, signature, **opts)
        self.class.ed25519_gem_required!
        opts = DEFAULT_SK_VERIFY_OPTS.merge(opts)
        unknown_opts = opts.keys - DEFAULT_SK_VERIFY_OPTS.keys
        raise UnsupportedError, "Verification options #{unknown_opts.inspect} are not supported." unless unknown_opts.empty?

        sig_algo, raw_sig, sk_flags, blob = build_signing_blob(application, signed_data, signature)

        if sig_algo != self.class.algorithm_identifier
          raise DecodeError, "bad signature algorithm: #{sig_algo.inspect}"
        end

        result = begin
            ed25519_key.verify(raw_sig, blob)
          rescue Ed25519::VerifyError
            false
          end

        # We don't know that the flags are correct until after we've validated the signature
        # which embeds the flags, so always verify the signature first.
        return false if opts[:user_presence_required] && (sk_flags & SK_FLAG_USER_PRESENCE != SK_FLAG_USER_PRESENCE)
        return false if opts[:user_verification_required] && (sk_flags & SK_FLAG_USER_VERIFICATION != SK_FLAG_USER_VERIFICATION)

        result
      end

      def ==(other)
        super && other.application == application
      end
    end
  end
end
