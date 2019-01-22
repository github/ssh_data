class SSHData::PublicKey::ED25519 < SSHData::PublicKey::Base
  attr_reader :pk

  def initialize(pk:)
    @pk = pk
  end
end
