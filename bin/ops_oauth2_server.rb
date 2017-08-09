# frozen_string_literal: true

require 'sinatra'
require 'sinatra/cookies'
require 'ops/oauth2/google'
require 'ops/oauth2/slack'
require 'ops/oauth2/auth'

# Main HTTPServer class handling requests
class HTTPServer < Sinatra::Base
  helpers Sinatra::Cookies

  slack = Slack.new
  google = Google.new

  set :port, 3000
  set :bind, '0.0.0.0'
  set :cookie_options, domain: Auth.cookie_domain, secure: true, httponly: true

  get '/oauth2/google/sign_in' do
    redirect google.oauth_auth_redirect
  end

  get '/oauth2/google/authorize' do
    return google.authorize(self)
  end

  get '/oauth2/slack/sign_in' do
    redirect slack.oauth_auth_redirect
  end

  get '/oauth2/slack/authorize' do
    return slack.authorize(self)
  end

  get '/oauth2/verify' do
    Auth.authorized?(cookies, request)
  end
end

HTTPServer.run!
