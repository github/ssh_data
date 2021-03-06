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
        raise UnsupportedError, "SK-Ed25519 verification is not supported."
      end

      def ==(other)
        super && other.application == application
      end
    end
  end
end
