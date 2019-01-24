class SSHData::PublicKey::Base
  attr_reader :algo

  def initialize(**kwargs)
    raise "implement me"
  end

  def verify(signed_data, signature)
    raise "implement me"
  end
end
