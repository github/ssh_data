module SSHData
  module PublicKey
    class Base
      attr_reader :algo

      def initialize(**kwargs)
        @algo = kwargs[:algo]
      end

      def verify(signed_data, signature)
        raise "implement me"
      end

      def ==(other)
        other.class == self.class
      end
    end
  end
end
