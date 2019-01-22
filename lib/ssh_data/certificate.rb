class SSHData::Certificate
  # Integer certificate types (denotes host vs. user)
  TYPE_USER = 1
  TYPE_HOST = 2

  # String certificate types (denotes key type).
  RSA_CERT_TYPE                 = "ssh-rsa-cert-v01@openssh.com"
  DSA_CERT_TYPE                 = "ssh-dss-cert-v01@openssh.com"
  ECDSA_SHA2_NISTP256_CERT_TYPE = "ecdsa-sha2-nistp256-cert-v01@openssh.com"
  ECDSA_SHA2_NISTP384_CERT_TYPE = "ecdsa-sha2-nistp384-cert-v01@openssh.com"
  ECDSA_SHA2_NISTP521_CERT_TYPE = "ecdsa-sha2-nistp521-cert-v01@openssh.com"
  ED25519_CERT_TYPE             = "ssh-ed25519-cert-v01@openssh.com"

  attr_reader :type_string, :nonce, :key_data, :serial, :type, :key_id,
              :valid_principals, :valid_after, :valid_before, :critical_options,
              :extensions, :reserved, :signature_key, :signature, :signed_data

  # Parse an SSH certificate.
  #
  # cert - An SSH formatted certificate, including key type, encoded key and
  #        optional user/host names.
  #
  # Returns a Certificate instance.
  def self.parse(cert)
    data = SSHData::Encoding.parse_certificate(cert)

    data[:valid_after]  = Time.at(data[:valid_after])
    data[:valid_before] = Time.at(data[:valid_before])

    # TODO: parse more fields, where possible

    new(**data)
  end

  # Intialize a new Certificate instance.
  #
  # type_string:      - The certificate's String type (one of RSA_CERT_TYPE,
  #                     DSA_CERT_TYPE, ECDSA_SHA2_NISTP256_CERT_TYPE,
  #                     ECDSA_SHA2_NISTP384_CERT_TYPE,
  #                     ECDSA_SHA2_NISTP521_CERT_TYPE, or ED25519_CERT_TYPE)
  # nonce:            - The certificate's String nonce field.
  # key_data:         - Hash of key-type-speciric data for public key.
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
  def initialize(type_string:, nonce:, key_data:, serial:, type:, key_id:, valid_principals:, valid_after:, valid_before:, critical_options:, extensions:, reserved:, signature_key:, signature:, signed_data:)
    @type_string = type_string
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
