require "abenity_ruby/version"
require "openssl"
require "base64"
require "net/https"
require "uri"
require "json"
require "nokogiri"
require "cgi"

module AbenityRuby
  class ApiClient
    PUBLIC_KEY = "-----BEGIN RSA PUBLIC KEY-----\n" +
      "MIGJAoGBALw1VRlS2vYgeIWhjyz+oUaZk4h7AC+BLgUxdZnzVBzyWQCVmv17XvXG\n" +
      "fg+Aqv5Ltix8K37VcrKjleasnJo1R79pGm0H3c0WfpGgXMTGB+mSijFwelZw/L4d\n" +
      "vl7SvA8MEDrN/KthGPy4r/UeV4USvi/y78ducmaIWg0naF9lefpDAgMBAAE=\n" +
      "-----END RSA PUBLIC KEY-----"

    # Public: Initialize an API Client
    #
    # api_username - A String of the API username
    # api_password - A String of the API password
    # api_key - A String of the API key
    # version - An Integer naming the API version number
    # environment - A String naming the environment
    # timeout - An Integer specifiying the timeout on a request
    def initialize(api_username, api_password, api_key, version = 2, environment = 'live', timeout = 10)
      @api_username = api_username
      @api_password = api_password
      @api_key = api_key
      @version = version

      if environment == 'live'
        @api_url = 'https://api.abenity.com'
      else
        @api_url = 'https://sandbox.abenity.com'
      end

      @timeout = timeout

      @encrypt_cipher = OpenSSL::Cipher.new("DES3")
      @encrypt_cipher.encrypt

      @triple_des_key = @encrypt_cipher.random_key
      @triple_des_iv = @encrypt_cipher.random_iv
    end

    # Public: Send a HTTP request to the API
    #
    # api_method - The API method to be called
    # http_method - The HTTP method to be used (GET, POST, PUT, DELETE, etc.)
    # data - Any data to be sent to the API
    #
    # Returns a data-object of the response
    def send_request(api_method, http_method = 'GET', data = nil)
      if data.is_a?(Hash)
        data['api_username'] = @api_username
        data['api_password'] = @api_password
        data['api_key'] = @api_key

        post_data = data.map{|k,v| "#{CGI::escape(k)}=#{CGI::escape(v)}"}.join('&')
      else
        post_data = sprintf(
            "api_username=%s&api_password=%s&api_key=%s&%s",
            CGI::escape(@api_username),
            CGI::escape(@api_password),
            CGI::escape(@api_key),
            data
        )
      end

      uri = URI.parse("#{@api_url}/v#{@version}/client#{api_method}")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE

      request = http_method == 'GET' ? Net::HTTP::Get.new(uri.request_uri) : Net::HTTP::Post.new(uri.request_uri)
      request.body = !data.nil? ? post_data : ''

      request.initialize_http_header({
        "User-Agent" => "abenity/abenity-ruby v1"
      })

      response = http.request(request)

      return parse_response(response.body)
    end

    # Public: Single Sign-On a member
    #
    # member_profile - A hash of key/value pairs that describes the member
    # private_key - Your RSA private key, used to sign your message
    #
    # Returns the raw API response
    def sso_member(member_profile, private_key)
      # Convert member profile hash to a HTTP query string
      payload_string = member_profile.map{|k,v| "#{k}=#{v}"}.join('&')

      # URL encode and Base 64 encode the IV
      iv_urlencoded = "#{CGI::escape(Base64.strict_encode64(@triple_des_iv))}decode"

      payload = encrypt_payload(payload_string, @triple_des_iv)
      cipher = encrypt_cipher(@triple_des_key)
      signature = sign_message(payload, private_key)

      data = sprintf(
          "Payload=%s&Cipher=%s&Signature=%s&Iv=%s",
          payload,
          cipher,
          signature,
          iv_urlencoded
      )

      return send_request('/sso_member.json', 'POST', data)
    end

    # Public: Deactivate a Member
    #
    # client_user_id - The unique Client User ID for the member
    # send_notification - Set to true to send a notification email
    #
    # Returns the raw API response
    def deactivate_member(client_user_id, send_notification = 'false')
      data = {
        'client_user_id' => client_user_id,
        'send_notification' => send_notification
      }

      return send_request('/deactivate_member.json', 'POST', data)
    end

    # Public: Reactivate a Member
    #
    # client_user_id - The unique Client User ID for the member
    # send_notification - Set to true to send a notification email
    #
    # Returns the raw API response
    def reactivate_member(client_user_id, send_notification = 'false')
      data = {
        'client_user_id' => client_user_id,
        'send_notification' => send_notification
      }

      return send_request('/reactivate_member.json', 'POST', data)
    end

    private

    # Private: Parse the API response
    #
    # response - The response string
    # format - The format of the response to parse
    #
    # Returns the parsed response as a data hash
    def parse_response(response, format = 'json')
      result = nil

      if format == 'json'
        result = JSON.parse(response)
      elsif format == 'xml'
        result = Nokogiri::XML(response)
      end

      return result
    end

    # Private: Symmetrically encrypt a string of information
    #
    # payload_string - An input string
    # iv - An initialization vector for Triple-DES in CBC mode
    #
    # Returns a base64-encoded and url-encoded representation of the $payload_string
    def encrypt_payload(payload_string, iv)
      payload_urlencoded = ''

      encrypted = @encrypt_cipher.update(payload_string) + @encrypt_cipher.final
      encypted_base64 = Base64.strict_encode64(encrypted)
      payload_urlencoded = "#{CGI::escape(encypted_base64)}decode"

      return payload_urlencoded
    end

    # Private: Asymmetrically encrypt a symmetrical encryption key
    #
    # triple_des_key - A Triple DES (3DES) encryption key
    #
    # Returns a base64-encoded and url-encoded representation of the $triple_des_key
    def encrypt_cipher(triple_des_key)
      triple_des_key_urlencoded = ''

      key = OpenSSL::PKey::RSA.new(PUBLIC_KEY)
      encrypted_triple_des = key.public_encrypt(triple_des_key)
      encrypted_base64 = Base64.strict_encode64(encrypted_triple_des)
      triple_des_key_urlencoded = "#{CGI::escape(encrypted_base64)}decode"

      return triple_des_key_urlencoded
    end

    # Private: Sign a message using a private RSA key
    #
    # payload - The message to be signed
    # private_key - An RSA private key
    #
    # Returns a base64-encoded and url-encoded hash of the $payload_string
    def sign_message(payload, private_key)
      signature_urlencoded = ''

      key = OpenSSL::PKey::RSA.new(private_key)

      payload_decoded = CGI::unescape(payload.chomp('decode'))

      signature = key.sign(OpenSSL::Digest::MD5.new, payload_decoded)
      signature_base64 = Base64.strict_encode64(signature)
      signature_urlencoded = "#{CGI::escape(signature_base64)}decode"

      return signature_urlencoded
    end
  end
end
