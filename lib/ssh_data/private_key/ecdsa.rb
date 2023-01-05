module SSHData
  module PrivateKey
    class ECDSA < Base
      attr_reader :curve, :public_key_bytes, :private_key_bytes, :openssl

      # Generate a new private key.
      #
      # curve - The String curve to use. One of SSHData::PublicKey::NISTP256,
      #         SSHData::PublicKey::NISTP384, or SSHData::PublicKey::NISTP521.
      #
      # Returns a PublicKey::Base subclass instance.
      def self.generate(curve)
        openssl_curve = PublicKey::ECDSA::OPENSSL_CURVE_NAME_FOR_CURVE[curve]
        raise AlgorithmError, "unknown curve: #{curve}" if openssl_curve.nil?

        openssl_key = OpenSSL::PKey::EC.generate(openssl_curve)
        from_openssl(openssl_key)
      end

      # Import an openssl private key.
      #
      # key - An OpenSSL::PKey::EC instance.
      #
      # Returns a DSA instance.
      def self.from_openssl(key)
        curve = PublicKey::ECDSA::CURVE_FOR_OPENSSL_CURVE_NAME[key.group.curve_name]
        algo = "ecdsa-sha2-#{curve}"

        new(
          algo: algo,
          curve: curve,
          public_key: key.public_key.to_bn.to_s(2),
          private_key: key.private_key,
          comment: "",
        )
      end

      def initialize(algo:, curve:, public_key:, private_key:, comment:)
        unless [PublicKey::ALGO_ECDSA256, PublicKey::ALGO_ECDSA384, PublicKey::ALGO_ECDSA521].include?(algo)
          raise DecodeError, "bad algorithm: #{algo.inspect}"
        end

        unless algo == "ecdsa-sha2-#{curve}"
          raise DecodeError, "bad curve: #{curve.inspect}"
        end

        @curve = curve
        @public_key_bytes = public_key
        @private_key_bytes = private_key

        super(algo: algo, comment: comment)

        @openssl = begin
          OpenSSL::PKey::EC.new(asn1.to_der)
        rescue ArgumentError
          raise DecodeError, "bad key data"
        end

        @public_key = PublicKey::ECDSA.new(
          algo: algo,
          curve: curve,
          public_key: public_key_bytes
        )
      end

      # Make an SSH signature.
      #
      # signed_data - The String message over which to calculated the signature.
      #
      # Returns a binary String signature.
      def sign(signed_data, algo: nil)
        algo ||= self.algo
        raise AlgorithmError unless algo == self.algo
        openssl_sig = openssl.sign(public_key.digest.new, signed_data)
        raw_sig = PublicKey::ECDSA.ssh_signature(openssl_sig)
        Encoding.encode_signature(algo, raw_sig)
      end

      private

      def asn1
        unless name = PublicKey::ECDSA::OPENSSL_CURVE_NAME_FOR_CURVE[curve]
          raise DecodeError, "unknown curve: #{curve.inspect}"
        end

        OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::Integer.new(1),
          OpenSSL::ASN1::OctetString.new(private_key_bytes.to_s(2)),
          OpenSSL::ASN1::ObjectId.new(name, 0, :EXPLICIT, :CONTEXT_SPECIFIC),
          OpenSSL::ASN1::BitString.new(public_key_bytes, 1, :EXPLICIT, :CONTEXT_SPECIFIC)
        ])
      end
    end
  end
end
