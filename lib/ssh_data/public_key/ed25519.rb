module SSHData
  module PublicKey
    class ED25519 < Base
      attr_reader :pk, :openssl

      @@alg_id = OpenSSL::ASN1::Sequence([
        OpenSSL::ASN1::ObjectId("1.3.101.112") # id-Ed25519
      ])

      def self.asn_algorithm_identifier
        @@alg_id
      end

      def self.algorithm_identifier
        ALGO_ED25519
      end

      def initialize(algo:, pk:)
        unless algo == self.class.algorithm_identifier
          raise DecodeError, "bad algorithm: #{algo.inspect}"
        end

        @pk = pk
        @openssl = OpenSSL::PKey.read(raw_to_subject_public_key_info_der(pk))

        super(algo: algo)
      end

      # Verify an SSH signature.
      #
      # signed_data - The String message that the signature was calculated over.
      # signature   - The binary String signature with SSH encoding.
      #
      # Returns boolean.
      def verify(signed_data, signature)
        sig_algo, raw_sig, _ = Encoding.decode_signature(signature)
        if sig_algo != self.class.algorithm_identifier
          raise DecodeError, "bad signature algorithm: #{sig_algo.inspect}"
        end

        return openssl.verify(nil, raw_sig, signed_data)
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

      private

      def raw_to_subject_public_key_info_der(key)
        OpenSSL::ASN1::Sequence([
          @@alg_id,
          OpenSSL::ASN1::BitString.new(key)
        ]).to_der
      end
    end
  end
end
