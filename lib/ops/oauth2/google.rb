# frozen_string_literal: true

require 'cgi'
require 'httparty'
require 'json'

# Basic support of google oauth2
class Google
  def oauth_client_secret
    ENV['GOOGLE_OAUTH_CLIENT_SECRET'] || configuration.dig('google_oauth_client_secret') || abort('Missing GOOGLE_OAUTH_CLIENT_SECRET')
  end

  def oauth_client_id
    ENV['GOOGLE_OAUTH_CLIENT_ID'] || configuration.dig('google_oauth_client_id') || abort('Missing GOOGLE_OAUTH_CLIENT_ID')
  end

  def redirect_url
    ENV['GOOGLE_OAUTH_REDIRECT_URL'] || configuration.dig('google_oauth_redirect_url') || abort('Missing GOOGLE_OAUTH_REDIRECT_URL')
  end

  def state_url
    ENV['OAUTH_SERVER_URL'] || configuration.dig('oauth_server_url') || abort('Missing OAUTH_SERVER_URL')
  end

  def oauth_auth_url
    'https://accounts.google.com/o/oauth2/auth'
  end

  def oauth_token_url
    'https://accounts.google.com/o/oauth2/token'
  end

  def oauth_userinfo_url
    'https://www.googleapis.com/oauth2/v2/userinfo'
  end

  def configuration_file
    '/etc/oauth2/oauth2.conf'
  end

  def configuration
    @configuration ||= JSON.parse(File.read(configuration_file))
  rescue
    abort("Missing or invalid #{configuration_file}")
  end

  def oauth_auth_url_params
    [
      "client_id=#{oauth_client_id}",
      'scope=email',
      'response_type=code',
      "redirect_uri=#{CGI.escape(redirect_url)}",
      "state=#{CGI.escape(state_url)}",
      'login_hint='
    ].join('&')
  end

  def oauth_auth_redirect
    [
      oauth_auth_url,
      '?',
      oauth_auth_url_params
    ].join
  end

  def user_info(authorization)
    headers = {
      'Authorization' => "Bearer #{authorization}"
    }
    HTTParty.get(oauth_userinfo_url, headers: headers)
  end

  def verify(code)
    # do not verify oauth code if not running as a server
    return {} unless configuration.dig('server')
    options = {
      body: {
        client_id: oauth_client_id,
        client_secret: oauth_client_secret,
        code: code,
        redirect_uri: redirect_url,
        grant_type: 'authorization_code'
      }
    }
    HTTParty.post(oauth_token_url, options)
  end
end
