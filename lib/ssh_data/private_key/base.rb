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
      #
      # Returns a binary String signature.
      def sign(signed_data)
        raise "implement me"
      end
    end
  end
end
