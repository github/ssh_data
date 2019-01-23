class SSHData::Certificate
  # Integer certificate types
  TYPE_USER = 1
  TYPE_HOST = 2

  # Certificate algorithm identifiers
  ALGO_RSA      = "ssh-rsa-cert-v01@openssh.com"
  ALGO_DSA      = "ssh-dss-cert-v01@openssh.com"
  ALGO_ECDSA256 = "ecdsa-sha2-nistp256-cert-v01@openssh.com"
  ALGO_ECDSA384 = "ecdsa-sha2-nistp384-cert-v01@openssh.com"
  ALGO_ECDSA521 = "ecdsa-sha2-nistp521-cert-v01@openssh.com"
  ALGO_ED25519  = "ssh-ed25519-cert-v01@openssh.com"

  attr_reader :algo, :nonce, :public_key, :serial, :type, :key_id,
              :valid_principals, :valid_after, :valid_before, :critical_options,
              :extensions, :reserved, :ca_key, :signature

  # Parse an SSH certificate.
  #
  # cert              - An SSH formatted certificate, including key algo,
  #                     encoded key and optional user/host names.
  # unsafe_no_verify: - Bool of whether to skip verifying certificate signature
  #                     (Default false)
  #
  # Returns a Certificate instance.
  def self.parse(cert, unsafe_no_verify: false)
    algo, b64, _ = cert.split(" ", 3)
    if algo.nil? || b64.nil?
      raise SSHData::DecodeError, "bad certificate format"
    end

    raw = Base64.decode64(b64)
    data, read = SSHData::Encoding.decode_certificate(raw)

    if read != raw.bytesize
      raise SSHData::DecodeError, "unexpected trailing data"
    end

    if data[:algo] != algo
      raise SSHData::DecodeError, "algo mismatch: #{data[:algo].inspect}!=#{algo.inspect}"
    end

    # Parse data into better types, where possible.
    data[:valid_after]  = Time.at(data[:valid_after])
    data[:valid_before] = Time.at(data[:valid_before])
    data[:public_key]   = SSHData::PublicKey.from_data(data.delete(:key_data))

    # The signature key is encoded as a string, but we can parse it.
    sk_raw = data.delete(:signature_key)
    sk_data, read = SSHData::Encoding.decode_public_key(sk_raw)
    if read != sk_raw.bytesize
      raise SSHData::DecodeError, "unexpected trailing data"
    end
    data[:ca_key] = SSHData::PublicKey.from_data(sk_data)

    unless unsafe_no_verify
      # The signature is the last field. The signature is calculated over all
      # preceding data.
      signed_data_len = raw.bytesize - data[:signature].bytesize - 4
      signed_data = raw.byteslice(0, signed_data_len)

      unless data[:ca_key].verify(signed_data, data[:signature])
        raise SSHData::VerifyError
      end
    end

    new(**data)
  end

  # Intialize a new Certificate instance.
  #
  # algo:             - The certificate's String algorithm id (one of ALGO_RSA,
  #                     ALGO_DSA, ALGO_ECDSA256, ALGO_ECDSA384, ALGO_ECDSA521,
  #                     or ALGO_ED25519)
  # nonce:            - The certificate's String nonce field.
  # public_key:       - The certificate's public key as an PublicKey::Base
  #                     subclass instance.
  # serial:           - The certificate's Integer serial field.
  # type:             - The certificate's Integer type field (one of TYPE_USER
  #                     or TYPE_HOST).
  # key_id:           - The certificate's String key_id field.
  # valid_principals: - The certificate's String valid_principals field.
  # valid_after:      - The certificate's Time valid_after field.
  # valid_before:     - The certificate's Time valid_before field.
  # critical_options: - The certificate's String critical_options field.
  # extensions:       - The certificate's String extensions field.
  # reserved:         - The certificate's String reserved field.
  # ca_key:           - The issuing CA's public key as a PublicKey::Base
  #                     subclass instance.
  # signature:        - The certificate's String signature field.
  #
  # Returns nothing.
  def initialize(algo:, nonce:, public_key:, serial:, type:, key_id:, valid_principals:, valid_after:, valid_before:, critical_options:, extensions:, reserved:, ca_key:, signature:)
    @algo = algo
    @nonce = nonce
    @public_key = public_key
    @serial = serial
    @type = type
    @key_id = key_id
    @valid_principals = valid_principals
    @valid_after = valid_after
    @valid_before = valid_before
    @critical_options = critical_options
    @extensions = extensions
    @reserved = reserved
    @ca_key = ca_key
    @signature = signature
  end
end