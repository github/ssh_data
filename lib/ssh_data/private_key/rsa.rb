module SSHData
  module PrivateKey
    class RSA < Base
      attr_reader :n, :e, :d, :iqmp, :p, :q, :openssl

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
