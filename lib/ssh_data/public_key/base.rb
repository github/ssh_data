class SSHData::PublicKey::Base
  def initialize(**kwargs)
    raise "implement me"
  end

  def verify(signed_data, signature)
    raise "implement me"
  end
end
