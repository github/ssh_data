  module SSHData
  module PrivateKey
    class DSA < Base
      attr_reader :p, :q, :g, :x, :y, :openssl

      # Generate a new private key.
      #
      # Returns a PublicKey::Base subclass instance.
      def self.generate
        from_openssl(OpenSSL::PKey::DSA.generate(1024))
      end

      # Import an openssl private key.
      #
      # key - An OpenSSL::PKey::DSA instance.
      #
      # Returns a DSA instance.
      def self.from_openssl(key)
        new(
          algo: PublicKey::ALGO_DSA,
          p: key.params["p"],
          q: key.params["q"],
          g: key.params["g"],
          y: key.params["pub_key"],
          x: key.params["priv_key"],
          comment: "",
        )
      end

      def initialize(algo:, p:, q:, g:, x:, y:, comment:)
        unless algo == PublicKey::ALGO_DSA
          raise DecodeError, "bad algorithm: #{algo.inspect}"
        end

        @p = p
        @q = q
        @g = g
        @x = x
        @y = y

        super(algo: algo, comment: comment)

        @openssl = OpenSSL::PKey::DSA.new(asn1.to_der)

        @public_key = PublicKey::DSA.new(algo: algo, p: p, q: q, g: g, y: y)
      end

      # Make an SSH signature.
      #
      # signed_data - The String message over which to calculated the signature.
      #
      # Returns a binary String signature.
      def sign(signed_data)
        openssl_sig = openssl.sign(OpenSSL::Digest::SHA1.new, signed_data)
        raw_sig = PublicKey::DSA.ssh_signature(openssl_sig)
        Encoding.encode_signature(algo, raw_sig)
      end

      private

      def asn1
        OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::Integer.new(0),
          OpenSSL::ASN1::Integer.new(p),
          OpenSSL::ASN1::Integer.new(q),
          OpenSSL::ASN1::Integer.new(g),
          OpenSSL::ASN1::Integer.new(y),
          OpenSSL::ASN1::Integer.new(x),
        ])
      end
    end
  end
end
