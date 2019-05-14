# frozen_string_literal: true

require 'cgi'
require 'httparty'
require 'json'
require 'cgi'

# Basic support of slack oauth2
class Slack
  def oauth_client_secret
    ENV['SLACK_OAUTH_CLIENT_SECRET'] || configuration.dig('slack', 'oauth_client_secret') || abort('Missing SLACK_OAUTH_CLIENT_SECRET')
  end

  def webhook_url
    configuration.dig('slack', 'webhook_url')
  end

  def oauth_client_id
    ENV['SLACK_OAUTH_CLIENT_ID'] || configuration.dig('slack', 'oauth_client_id') || abort('Missing SLACK_OAUTH_CLIENT_ID')
  end

  def redirect_url
    ENV['SLACK_OAUTH_REDIRECT_URL'] || configuration.dig('slack', 'oauth_redirect_url') || abort('Missing SLACK_OAUTH_REDIRECT_URL')
  end

  def whitelisted_domains
    return ENV['SLACK_WHITELISTED_DOMAINS'].split(',') if ENV['SLACK_WHITELISTED_DOMAINS']
    configuration.dig('slack', 'whitelisted_domains') || abort('Missing SLACK_WHITELISTED_DOMAINS')
  end

  def oauth_auth_url
    'https://slack.com/oauth/authorize'
  end

  def oauth_token_url
    'https://slack.com/api/oauth.access'
  end

  def oauth_scopes
    'identity.basic,identity.avatar,identity.team'
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

  def authorize(s)
    response = verify(s.params)
    return 403 unless response.dig('ok')

    if webhook_url
      body = "```Authorizing:\n" \
             "  User: #{response.dig('user', 'name')}\n" \
             "  Team: #{response.dig('team', 'name')}\n" \
             "```"
      icon_url = response.dig('user', 'image_48')
      notify(body, icon_url)
    end

    # get slack response domain and authorize if included in whitelisted
    return 403 unless whitelisted_domains.include? domain(response.body)

    # make sure we get a proper user info structure
    ui = user_info(response.body)
    return 403 unless ui

    # build and authorize cookies
    Auth.authorize(ui, s.request).each do |cookie, value|
      s.cookies.set(cookie, value: value, expires: Time.now + Auth.cookie_ttl)
    end

    # redirect user to a proper place if needed
    if s.cookies.key?(Auth.cookie_name_redirect)
      redirect_url = s.cookies[Auth.cookie_name_redirect]
      s.cookies.delete(Auth.cookie_name_redirect)
      s.redirect redirect_url
    end

    # redirect to a default page
    s.redirect Auth.default_redirect_page
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

  def notify(text, icon_url=nil)
    headers = { 'Content-Type' => 'application/json' }
    body = { 'text': text, username: 'Intranet', 'channel': '#intranet-events' }

    if icon_url
      body['icon_url'] = icon_url
    else
      body['icon_emoji'] = ':unlock:'
    end

    begin
      r = HTTParty.post(webhook_url, body: body.to_json, headers: headers )
      return (r.code == 200)
    rescue
      return false
    end
  end
end
