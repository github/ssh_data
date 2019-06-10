module SSHData
  module PrivateKey
    class Base
      attr_reader :algo, :comment, :public_key

      def initialize(**kwargs)
        @algo = kwargs[:algo]
        @comment = kwargs[:comment]
      end

      # Generate a new private key.
      #
      # Returns a PublicKey::Base subclass instance.
      def self.generate(**kwargs)
        raise "implement me"
      end

      # Make an SSH signature.
      #
      # signed_data - The String message over which to calculated the signature.
      # algo:       - Optionally specify the signature algorithm to use.
      #
      # Returns a binary String signature.
      def sign(signed_data, algo: nil)
        raise "implement me"
      end

      # Issue a certificate using this private key.
      #
      # signature_algo: - Optionally specify the signature algorithm to use.
      # kwargs          - See SSHData::Certificate.new.
      #
      # Returns a SSHData::Certificate instance.
      def issue_certificate(signature_algo: nil, **kwargs)
        Certificate.new(**kwargs).tap { |c| c.sign(self, algo: signature_algo) }
      end
    end
  end
end
