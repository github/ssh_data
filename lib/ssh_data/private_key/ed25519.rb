module SSHData
  module PrivateKey
    class ED25519 < Base
      attr_reader :pk, :sk, :openssl

      # Generate a new private key.
      #
      # Returns a PublicKey::Base subclass instance.
      def self.generate
        from_openssl(OpenSSL::PKey.generate_key("ED25519"))
      end

      # Create from a ::OpenSSL::PKey::PKey instance.
      #
      # key - A ::OpenSSL::PKey::PKey instance.
      #
      # Returns a ED25519 instance.
      def self.from_openssl(key)
        new(
          algo: PublicKey::ALGO_ED25519,
          pk: key.raw_public_key,
          sk: key.raw_private_key + key.raw_public_key,
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

        @openssl = OpenSSL::PKey.read(raw_to_private_key_info_der(sk.byteslice(0, 32)))

        if @openssl.raw_public_key != pk
          raise DecodeError, "bad pk"
        end

        @public_key = PublicKey::ED25519.new(algo: algo, pk: pk)
      end

      # Make an SSH signature.
      #
      # signed_data - The String message over which to calculated the signature.
      #
      # Returns a binary String signature.
      def sign(signed_data, algo: nil)
        algo ||= self.algo
        raise AlgorithmError unless algo == self.algo
        raw_sig = openssl.sign(nil, signed_data)
        Encoding.encode_signature(algo, raw_sig)
      end

      private

      def raw_to_private_key_info_der(key)
        inner_octet_string = OpenSSL::ASN1::OctetString.new(key)
        private_key_field = OpenSSL::ASN1::OctetString.new(inner_octet_string.to_der)
        version = OpenSSL::ASN1::Integer.new(0)
        OpenSSL::ASN1::Sequence.new([
          version,
          PublicKey::ED25519.asn_algorithm_identifier,
          private_key_field
        ]).to_der
      end
    end
  end
end
