class SSHData::PublicKey::ED25519 < SSHData::PublicKey::Base
  attr_reader :pk

  # ed25519 isn't a hard requirement for using this Gem. We only do actual
  # validation with the key if the ed25519 Gem has been loaded.
  def self.enabled?
    Object.const_defined?(:Ed25519)
  end

  def initialize(pk:)
    @pk = pk
  end

  def verify(signed_data, signature)
    unless self.class.enabled?
      raise SSHData::VerifyError, "the ed25519 gem isn't loadedd"
    end

    sig_algo, raw_sig, _ = SSHData::Encoding.decode_signature(signature)
    if sig_algo != SSHData::PublicKey::ALGO_ED25519
      raise SSHData::DecodeError, "bad signature algorithm: #{sig_algo.inspect}"
    end

    begin
      ed25519_key.verify(raw_sig, signed_data)
    rescue Ed25519::VerifyError
      false
    end
  end

  def ed25519_key
    return nil unless self.class.enabled?
    @ed25519_key ||= Ed25519::VerifyKey.new(pk)
  end
end
