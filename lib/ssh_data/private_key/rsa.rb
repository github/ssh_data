module SSHData
  module PrivateKey
    class RSA < Base
      attr_reader :n, :e, :d, :iqmp, :p, :q, :openssl


      # Generate a new private key.
      #
      # size                    - The Integer key size to generate.
      # unsafe_allow_small_key: - Bool of whether to allow keys of less than
      #                           2048 bits.
      #
      # Returns a PublicKey::Base subclass instance.
      def self.generate(size, unsafe_allow_small_key: false)
        unless size >= 2048 || unsafe_allow_small_key
          raise AlgorithmError, "key too small"
        end

        from_openssl(OpenSSL::PKey::RSA.generate(size))
      end

      # Import an openssl private key.
      #
      # key - An OpenSSL::PKey::RSA instance.
      #
      # Returns a RSA instance.
      def self.from_openssl(key)
        new(
          algo: PublicKey::ALGO_RSA,
          n: key.params["n"],
          e: key.params["e"],
          d: key.params["d"],
          iqmp: key.params["iqmp"],
          p: key.params["p"],
          q: key.params["q"],
          comment: "",
        )
      end

      def initialize(algo:, n:, e:, d:, iqmp:, p:, q:, comment:)
        unless algo == PublicKey::ALGO_RSA
          raise DecodeError, "bad algorithm: #{algo.inspect}"
        end

        @n = n
        @e = e
        @d = d
        @iqmp = iqmp
        @p = p
        @q = q

        super(algo: algo, comment: comment)

        @openssl = OpenSSL::PKey::RSA.new(asn1.to_der)

        @public_key = PublicKey::RSA.new(algo: algo, e: e, n: n)
      end

      # Make an SSH signature.
      #
      # signed_data - The String message over which to calculated the signature.
      #
      # Returns a binary String signature.
      def sign(signed_data, algo: nil)
        algo ||= self.algo
        digest = PublicKey::RSA::ALGO_DIGESTS[algo]
        raise AlgorithmError if digest.nil?
        raw_sig = openssl.sign(digest.new, signed_data)
        Encoding.encode_signature(algo, raw_sig)
      end

      private

      # CRT coefficient for faster RSA operations. Used by OpenSSL, but not
      # OpenSSH.
      #
      # Returns an OpenSSL::BN instance.
      def dmp1
        d % (p - 1)
      end

      # CRT coefficient for faster RSA operations. Used by OpenSSL, but not
      # OpenSSH.
      #
      # Returns an OpenSSL::BN instance.
      def dmq1
        d % (q - 1)
      end

      def asn1
        OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::Integer.new(0),
          OpenSSL::ASN1::Integer.new(n),
          OpenSSL::ASN1::Integer.new(e),
          OpenSSL::ASN1::Integer.new(d),
          OpenSSL::ASN1::Integer.new(p),
          OpenSSL::ASN1::Integer.new(q),
          OpenSSL::ASN1::Integer.new(dmp1),
          OpenSSL::ASN1::Integer.new(dmq1),
          OpenSSL::ASN1::Integer.new(iqmp),
        ])
      end

    end
  end
end
