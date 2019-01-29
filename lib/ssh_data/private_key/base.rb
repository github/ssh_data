module SSHData
  module PrivateKey
    class Base
      attr_reader :algo, :comment

      def initialize(**kwargs)
        @algo = kwargs[:algo]
        @comment = kwargs[:comment]
      end
    end
  end
end
