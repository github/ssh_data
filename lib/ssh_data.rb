require "openssl"
require "base64"

module SSHData
  # Break down a key in OpenSSH authorized_keys format (see sshd(8) manual
  # page).
  #
  # key - An OpenSSH formatted public key or certificate, including algo,
  #       base64 encoded key and optional comment.
  #
  # Returns an Array containing the algorithm String , the raw key or
  # certificate String and the comment String or nil.
  def key_parts(key)
    algo, b64, comment = key.strip.split(" ", 3)
    if algo.nil? || b64.nil?
      raise DecodeError, "bad data format"
    end

    raw = begin
      Base64.strict_decode64(b64)
    rescue ArgumentError
      raise DecodeError, "bad data format"
    end

    [algo, raw, comment]
  end

  extend self
end

require "ssh_data/version"
require "ssh_data/error"
require "ssh_data/certificate"
require "ssh_data/public_key"
require "ssh_data/private_key"
require "ssh_data/encoding"
require "ssh_data/signature"
