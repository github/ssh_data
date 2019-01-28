module SSHData
  module PublicKey
    class ED25519 < Base
      attr_reader :pk, :ed25519_key

      # ed25519 isn't a hard requirement for using this Gem. We only do actual
      # validation with the key if the ed25519 Gem has been loaded.
      def self.enabled?
        Object.const_defined?(:Ed25519)
      end

      def initialize(algo:, pk:)
        unless algo == ALGO_ED25519
          raise DecodeError, "bad algorithm: #{algo.inpsect}"
        end

        @algo = algo
        @pk = pk

        if self.class.enabled?
          @ed25519_key = Ed25519::VerifyKey.new(pk)
        end
      end

      # Verify an SSH signature.
      #
      # signed_data - The String message that the signature was calculated over.
      # signature   - The binarty String signature with SSH encoding.
      #
      # Returns boolean.
      def verify(signed_data, signature)
        unless self.class.enabled?
          raise VerifyError, "the ed25519 gem isn't loadedd"
        end

        sig_algo, raw_sig, _ = Encoding.decode_signature(signature)
        if sig_algo != ALGO_ED25519
          raise DecodeError, "bad signature algorithm: #{sig_algo.inspect}"
        end

        begin
          ed25519_key.verify(raw_sig, signed_data)
        rescue Ed25519::VerifyError
          false
        end
      end
    end
  end
end
