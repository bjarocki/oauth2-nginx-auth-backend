# frozen_string_literal: true

require 'base64'
require 'json'
require 'openssl'

# Authorization
class Auth
  def cookie_name_permissions
    ENV['OAUTH_COOKIE_NAME_PERMISSIONS'] || configuration.dig('cookie_name_permissions') || abort('Missing OAUTH_COOKIE_NAME_PERMISSIONS')
  end

  def cookie_name_signature
    'OKIntranetSignature'
    ENV['OAUTH_COOKIE_NAME_SIGNATURE'] || configuration.dig('cookie_name_signature') || abort('Missing OAUTH_COOKIE_NAME_SIGNATURE')
  end

  def cookie_name_redirect
    ENV['OAUTH_COOKIE_NAME_REDIRECT'] || configuration.dig('cookie_name_redirect') || abort('Missing OAUTH_COOKIE_NAME_REDIRECT')
  end

  def header_request_redirect_url
    'HTTP_X_AUTH_REQUEST_REDIRECT'
  end

  def environment
    ENV['OAUTH_ENVIRONMENT'] || configuration.dig('running_environment') || abort('Missing OAUTH_ENVIRONMENT')
  end

  def secret
    ENV['OAUTH_SHARED_SECRET'] || configuration.dig('oauth_shared_secret') || abort('Missing OAUTH_SHARED_SECRET')
  end

  def default_redirect_page
    ENV['DEFAULT_REDIRECT_PAGE'] || configuration.dig('default_redirect_page') || abort('Missing DEFAULT_REDIRECT_PAGE')
  end

  def cookie_domain
    ENV['OAUTH_COOKIE_DOMAIN'] || configuration.dig('cookie_domain') || abort('Missing OAUTH_COOKIE_DOMAIN')
  end

  def cookie_ttl
    return ENV['OAUTH_COOKIE_TTL'].to_i if ENV['OAUTH_COOKIE_TTL']
    configuration.dig('cookie_ttl').to_i || abort('Missing OAUTH_COOKIE_TTL')
  end

  def sign(data)
    digest = OpenSSL::Digest.new('sha256')
    Base64.encode64(OpenSSL::HMAC.digest(digest, secret, data))
  end

  def trusted?(cookies, request)
    cookies[cookie_name_signature] == sign([cookies[cookie_name_permissions], request.user_agent].join)
  end

  def configuration_file
    '/etc/oauth2/oauth2.conf'
  end

  def configuration
    @configuration ||= JSON.parse(File.read(configuration_file))
  rescue
    abort("Missing or invalid #{configuration_file}")
  end

  def authorize(info, request)
    cookies = {}
    cookies[cookie_name_permissions] = Base64.encode64(info.to_json)
    cookies[cookie_name_signature] = sign([Base64.encode64(info.to_json), request.user_agent].join)
    cookies
  end

  def go_to_auth(cookies, request)
    cookies[cookie_name_redirect] = request.env[header_request_redirect_url]
    401
  end

  def untrusted(cookies, request)
    cookies.delete(cookie_name_signature)
    cookies.delete(cookie_name_permissions)
    go_to_auth(cookies, request)
  end

  def authorized?(cookies, request)
    return go_to_auth(cookies, request) unless cookies.key?(cookie_name_permissions)
    return go_to_auth(cookies, request) unless cookies.key?(cookie_name_signature)
    return untrusted(cookies, request) unless trusted?(cookies, request)
    200
  end
end
