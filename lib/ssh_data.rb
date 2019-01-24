require "openssl"
require "base64"

module SSHData
  # Break down a public key or certificate into its algorith, raw key, and host.
  #
  # key - An SSH formatted public key or certificate, including algo, encoded
  #       key and optional user/host names.
  #
  # Returns an Array containing the algorithm String , the raw key or
  # certificate String and the host String or nil.
  def key_parts(key)
    algo, b64, host = key.strip.split(" ", 3)
    if algo.nil? || b64.nil?
      raise DecodeError, "bad data format"
    end

    raw = begin
      Base64.strict_decode64(b64)
    rescue ArgumentError
      raise DecodeError, "bad data format"
    end

    [algo, raw, host]
  end

  extend self
end

require "ssh_data/version"
require "ssh_data/error"
require "ssh_data/certificate"
require "ssh_data/public_key"
require "ssh_data/encoding"
