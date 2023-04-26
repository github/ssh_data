module SSHData
  module PublicKey
    class RSA < Base
      attr_reader :e, :n, :openssl

      ALGO_DIGESTS = {
        ALGO_RSA          => OpenSSL::Digest::SHA1,
        ALGO_RSA_SHA2_256 => OpenSSL::Digest::SHA256,
        ALGO_RSA_SHA2_512 => OpenSSL::Digest::SHA512
      }

      def initialize(algo:, e:, n:)
        unless algo == ALGO_RSA
          raise DecodeError, "bad algorithm: #{algo.inspect}"
        end

        @algo = algo
        @e = e
        @n = n

        @openssl = OpenSSL::PKey::RSA.new(asn1.to_der)

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
        digest = ALGO_DIGESTS[sig_algo]

        if digest.nil?
          raise DecodeError, "bad signature algorithm: #{sig_algo.inspect}"
        end

        # OpenSSH compatibility: if a the number of bytes in the signature is less than the number of bytes of the RSA
        # modulus, prepend the signature with zeros.
        # See https://github.com/openssh/openssh-portable/blob/ac383f3a5c6f529a2e8a5bc44af79a08c7da294e/ssh-rsa.c#L531
        difference = n.num_bytes - raw_sig.bytesize
        raw_sig = "\0" * difference + raw_sig if difference.positive?

        openssl.verify(digest.new, raw_sig, signed_data)
      end

      # RFC4253 binary encoding of the public key.
      #
      # Returns a binary String.
      def rfc4253
        Encoding.encode_fields(
          [:string, algo],
          [:mpint,  e],
          [:mpint,  n]
        )
      end

      # Is this public key equal to another public key?
      #
      # other - Another SSHData::PublicKey::Base instance to compare with.
      #
      # Returns boolean.
      def ==(other)
        super && other.e == e && other.n == n
      end

      private

      def asn1
        OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::Sequence.new([
            OpenSSL::ASN1::ObjectId.new("rsaEncryption"),
            OpenSSL::ASN1::Null.new(nil),
          ]),
          OpenSSL::ASN1::BitString.new(OpenSSL::ASN1::Sequence.new([
            OpenSSL::ASN1::Integer.new(n),
            OpenSSL::ASN1::Integer.new(e),
          ]).to_der),
        ])
      end
    end
  end
end
