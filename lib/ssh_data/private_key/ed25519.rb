module SSHData
  module PrivateKey
    class ED25519 < Base
      attr_reader :pk, :sk, :ed25519_key

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
    end
  end
end
