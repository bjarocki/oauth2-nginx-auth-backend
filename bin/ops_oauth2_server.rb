# frozen_string_literal: true

require 'sinatra'
require 'sinatra/cookies'
require 'ops/oauth2/slack'
require 'ops/oauth2/auth'

# Main HTTPServer class handling requests
class HTTPServer < Sinatra::Base
  helpers Sinatra::Cookies

  slack = Slack.new
  auth = Auth.new

  set :port, 3000
  set :cookie_options, domain: auth.cookie_domain, secure: true, httponly: true

  get '/oauth2/sign_in' do
    redirect slack.oauth_auth_redirect
  end

  get '/oauth2/slack' do
    response = slack.verify(params)
    return 403 unless response.dig('ok')

    # get slack response domain and authorize if included in whitelisted
    return 403 unless slack.whitelisted_domains.include? slack.domain(response.body)

    # make sure we get a proper user info structure
    user_info = slack.user_info(response.body)
    return 403 unless user_info

    # build and authorize cookies
    auth.authorize(user_info, request).each do |cookie, value|
      cookies.set(cookie, {value: value, expires: Time.now + auth.cookie_ttl}
    end

    # redirect user to a proper place if needed
    if cookies.key?(auth.cookie_name_redirect)
      redirect_url = cookies[auth.cookie_name_redirect]
      cookies.delete(auth.cookie_name_redirect)
      redirect redirect_url
    end

    # redirect to a default page
    redirect auth.default_redirect_page
  end

  get '/oauth2/verify' do
    auth.authorized?(cookies, request)
  end
end

HTTPServer.run!
