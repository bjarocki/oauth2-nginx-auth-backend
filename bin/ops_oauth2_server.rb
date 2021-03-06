# frozen_string_literal: true

require 'sinatra'
require 'sinatra/cookies'
require 'ops/oauth2/google'
require 'ops/oauth2/slack'
require 'ops/oauth2/auth'
require 'ops/oauth2/email'

# Main HTTPServer class handling requests
class HTTPServer < Sinatra::Base
  helpers Sinatra::Cookies

  slack = Slack.new
  google = Google.new
  email = Email.new

  set :port, 3000
  set :bind, '0.0.0.0'
  set :cookie_options, domain: Auth.cookie_domain, secure: true, httponly: true
  set :public_folder, 'static'
  set :views, Proc.new { File.join(root, "..", "views") }
  set :environment, :production

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

  get '/oauth2/sign_in' do
    erb :index, :locals => { :providers => Auth.configuration.keys }
  end

  get '/oauth2/email/authorize' do
    if 200 == email.authorize(self)
      erb :good, :locals => { :services => email.configuration.dig("services", "list") }
    else
      403
    end
  end

  get '/oauth2/email/generate' do
    erb :email
  end

  post '/oauth2/email/generate' do
    email.generate(self)
    erb :email_thankyou
  end
end

HTTPServer.run!
