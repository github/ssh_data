module SSHData
  module PublicKey
    class Base
      attr_reader :algo

      def initialize(**kwargs)
        @algo = kwargs[:algo]
      end

      # Calculate the fingerprint of this public key.
      #
      # md5: - Bool of whether to generate an MD5 fingerprint instead of the
      #        default SHA256.
      #
      # Returns a String fingerprint.
      def fingerprint(md5: false)
        if md5
          # colon separated, hex encoded md5 digest
          OpenSSL::Digest::MD5.digest(raw).unpack("H2" * 16).join(":")
        else
          # base64 encoded sha256 digest with b64 padding stripped
          Base64.strict_encode64(OpenSSL::Digest::SHA256.digest(raw))[0...-1]
        end
      end

      # Verify an SSH signature.
      #
      # signed_data - The String message that the signature was calculated over.
      # signature   - The binarty String signature with SSH encoding.
      #
      # Returns boolean.
      def verify(signed_data, signature)
        raise "implement me"
      end

      # Raw encoding of public key.
      #
      # Returns a binary String.
      def raw
        raise "implement me"
      end

      # OpenSSH public key in authorized_keys format (see sshd(8) manual page).
      #
      # comment - Optional String comment to append.
      #
      # Returns a String key.
      def openssh(comment: nil)
        [algo, Base64.strict_encode64(raw), comment].compact.join(" ")
      end

      # Is this public key equal to another public key?
      #
      # other - Another SSHData::PublicKey::Base instance to compare with.
      #
      # Returns boolean.
      def ==(other)
        other.class == self.class
      end
    end
  end
end
