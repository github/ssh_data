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

  attr_reader :algo, :nonce, :key_data, :serial, :type, :key_id,
              :valid_principals, :valid_after, :valid_before, :critical_options,
              :extensions, :reserved, :signature_key, :signature, :signed_data

  # Parse an SSH certificate.
  #
  # cert - An SSH formatted certificate, including key algo, encoded key and
  #        optional user/host names.
  #
  # Returns a Certificate instance.
  def self.parse(cert)
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

    # The signature is the last field. The signature is calculated over all
    # preceding data.
    signed_data_len = raw.bytesize - data[:signature].bytesize
    data[:signed_data] = raw.byteslice(0, signed_data_len)

    new(**data)
  end

  # Intialize a new Certificate instance.
  #
  # algo:             - The certificate's String algorithm id (one of ALGO_RSA,
  #                     ALGO_DSA, ALGO_ECDSA256, ALGO_ECDSA384, ALGO_ECDSA521,
  #                     or ALGO_ED25519)
  # nonce:            - The certificate's String nonce field.
  # key_data:         - Hash of key-type-specific data for public key.
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
  # signature_key:    - The certificate's String signature_key field.
  # signature:        - The certificate's String signature field.
  # signed_data:      - The String data over which the signature was calculated.
  #                     This isn't an actual field in the certificate, but is
  #                     calculated during parsing.
  #
  # Returns nothing.
  def initialize(algo:, nonce:, key_data:, serial:, type:, key_id:, valid_principals:, valid_after:, valid_before:, critical_options:, extensions:, reserved:, signature_key:, signature:, signed_data:)
    @algo = algo
    @nonce = nonce
    @key_data = key_data
    @serial = serial
    @type = type
    @key_id = key_id
    @valid_principals = valid_principals
    @valid_after = valid_after
    @valid_before = valid_before
    @critical_options = critical_options
    @extensions = extensions
    @reserved = reserved
    @signature_key = signature_key
    @signature = signature
    @signed_data = signed_data
  end
end
