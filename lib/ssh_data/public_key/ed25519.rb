module SSHData
  module PublicKey
    class ED25519 < Base
      attr_reader :pk, :ed25519_key

      # ed25519 isn't a hard requirement for using this Gem. We only do actual
      # validation with the key if the ed25519 Gem has been loaded.
      def self.enabled?
        Object.const_defined?(:Ed25519)
      end

      # Assert that the ed25519 gem has been loaded.
      #
      # Returns nothing, raises AlgorithmError.
      def self.ed25519_gem_required!
        raise AlgorithmError, "the ed25519 gem is not loaded" unless enabled?
      end

      def self.algorithm_identifier
        ALGO_ED25519
      end

      def initialize(algo:, pk:)
        unless algo == self.class.algorithm_identifier
          raise DecodeError, "bad algorithm: #{algo.inspect}"
        end

        @pk = pk

        if self.class.enabled?
          @ed25519_key = Ed25519::VerifyKey.new(pk)
        end

        super(algo: algo)
      end

      # Verify an SSH signature.
      #
      # signed_data - The String message that the signature was calculated over.
      # signature   - The binary String signature with SSH encoding.
      #
      # Returns boolean.
      def verify(signed_data, signature)
        self.class.ed25519_gem_required!

        sig_algo, raw_sig, _ = Encoding.decode_signature(signature)
        if sig_algo != self.class.algorithm_identifier
          raise DecodeError, "bad signature algorithm: #{sig_algo.inspect}"
        end

        begin
          ed25519_key.verify(raw_sig, signed_data)
        rescue Ed25519::VerifyError
          false
        end
      end

      # RFC4253 binary encoding of the public key.
      #
      # Returns a binary String.
      def rfc4253
        Encoding.encode_fields(
          [:string, algo],
          [:string, pk],
        )
      end

      # Is this public key equal to another public key?
      #
      # other - Another SSHData::PublicKey::Base instance to compare with.
      #
      # Returns boolean.
      def ==(other)
        super && other.pk == pk
      end
    end
  end
end
