# frozen_string_literal: true

require 'cgi'
require 'httparty'
require 'json'

# Basic support of slack oauth2
class Slack
  def oauth_client_secret
    ENV['SLACK_OAUTH_CLIENT_SECRET'] || configuration.dig('slack_oauth_client_secret') || abort('Missing SLACK_OAUTH_CLIENT_SECRET')
  end

  def oauth_client_id
    ENV['SLACK_OAUTH_CLIENT_ID'] || configuration.dig('slack_oauth_client_id') || abort('Missing SLACK_OAUTH_CLIENT_ID')
  end

  def redirect_url
    ENV['SLACK_OAUTH_REDIRECT_URL'] || configuration.dig('slack_oauth_redirect_url') || abort('Missing SLACK_OAUTH_REDIRECT_URL')
  end

  def whitelisted_domains
    return ENV['SLACK_WHITELISTED_DOMAINS'].split(',') if ENV['SLACK_WHITELISTED_DOMAINS']
    return configuration.dig('slack_whitelisted_domains') || abort('Missing SLACK_WHITELISTED_DOMAINS')
  end

  def oauth_auth_url
    'https://slack.com/oauth/authorize'
  end

  def oauth_token_url
    'https://slack.com/api/oauth.access'
  end

  def oauth_scopes
    'identity.basic,identity.team'
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
      "scope=#{oauth_scopes}",
      "redirect_uri=#{CGI.escape(redirect_url)}"
    ].join('&')
  end

  def oauth_auth_redirect
    [
      oauth_auth_url,
      '?',
      oauth_auth_url_params
    ].join
  end

  def user_info(response)
    payload = JSON.parse(response)
    {
      'user': payload['user']
    }
  rescue
    nil
  end

  def domain(response)
    payload = JSON.parse(response)
    payload.dig('team', 'domain')
  rescue
    nil
  end

  def verify(params)
    return { 'ok': false } unless params.dig('code')
    options = {
      body: {
        client_id: oauth_client_id,
        client_secret: oauth_client_secret,
        code: params.dig('code'),
        redirect_uri: redirect_url
      }
    }
    HTTParty.post(oauth_token_url, options)
  end
end
