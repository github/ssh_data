module SSHData
  module PrivateKey
    class Base
      attr_reader :algo, :comment, :public_key

      def initialize(**kwargs)
        @algo = kwargs[:algo]
        @comment = kwargs[:comment]
      end
    end
  end
end
