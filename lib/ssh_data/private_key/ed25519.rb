module SSHData
  module PrivateKey
    class ED25519 < Base
      attr_reader :pk, :sk, :ed25519_key

      # Generate a new private key.
      #
      # Returns a PublicKey::Base subclass instance.
      def self.generate
        PublicKey::ED25519.ed25519_gem_required!
        from_ed25519(Ed25519::SigningKey.generate)
      end

      # Create from a ::Ed25519::SigningKey instance.
      #
      # key - A ::Ed25519::SigningKey instance.
      #
      # Returns a ED25519 instance.
      def self.from_ed25519(key)
        new(
          algo: PublicKey::ALGO_ED25519,
          pk: key.verify_key.to_bytes,
          sk: key.to_bytes + key.verify_key.to_bytes,
          comment: "",
        )
      end

      def initialize(algo:, pk:, sk:, comment:)
        unless algo == PublicKey::ALGO_ED25519
          raise DecodeError, "bad algorithm: #{algo.inspect}"
        end

        # openssh stores the pk twice, once as half of the sk...
        if sk.bytesize != 64 || sk.byteslice(32, 32) != pk
          raise DecodeError, "bad sk"
        end

        @pk = pk
        @sk = sk

        super(algo: algo, comment: comment)

        if PublicKey::ED25519.enabled?
          @ed25519_key = Ed25519::SigningKey.new(sk.byteslice(0, 32))

          if @ed25519_key.verify_key.to_bytes != pk
            raise DecodeError, "bad pk"
          end
        end

        @public_key = PublicKey::ED25519.new(algo: algo, pk: pk)
      end

      # Make an SSH signature.
      #
      # signed_data - The String message over which to calculated the signature.
      #
      # Returns a binary String signature.
      def sign(signed_data, algo: nil)
        PublicKey::ED25519.ed25519_gem_required!
        algo ||= self.algo
        raise AlgorithmError unless algo == self.algo
        raw_sig = ed25519_key.sign(signed_data)
        Encoding.encode_signature(algo, raw_sig)
      end
    end
  end
end
