# frozen_string_literal: true

require 'json'
require 'ops/oauth2/auth'
require 'mail'
require 'erb'

class Email
  def initialize
    email_options ||= { :address  => configuration.dig("email", "smtp", "host"),
            :port                 => configuration.dig("email", "smtp", "port"),
            :domain               => configuration.dig("email", "smtp", "domain"),
            :user_name            => configuration.dig("email", "smtp", "user"),
            :password             => configuration.dig("email", "smtp", "password"),
            :authentication       => 'plain',
            :enable_starttls_auto => true  }
    Mail.defaults do
      delivery_method :smtp, email_options
    end
  end

  def email_users_list
    ENV['EMAIL_USERS_LIST'] || configuration.dig('email', 'users_list') || abort('Missing EMAIL_USERS_LIST')
  end

  def configuration
    @configuration ||= JSON.parse(File.read(configuration_file))
  rescue
    abort("Missing or invalid #{configuration_file}")
  end

  def configuration_file
    '/etc/oauth2/oauth2.conf'
  end

  def generate(s)
    return 403 unless s.params.key? 'email'
    return 403 unless email_users_list.include? s.params['email']
    payload = Base64.urlsafe_encode64({"expire": (Time.now.to_i + 3600), "email": s.params['email']}.to_json)
    signature = Auth.sign([payload, s.request.user_agent].join).chomp
    from = configuration.dig("email", "smtp", "mail_from")
    html = ERB.new(File.read('templates/email-token.erb'))
    action_link = "https://auth.otwarte.xyz/oauth2/email/authorize?payload=#{payload}&signature=#{signature}"
    Mail.deliver do
       to s.params['email']
       from from
       subject '[OK][Access] Granted.'
       html_part do
         content_type 'text/html; charset=UTF-8'
         body html.result(binding)
       end
    end
  end

  def authorize(s)
    return 403 unless s.params.key? 'payload'
    return 403 unless s.params.key? 'signature'
    return 403 unless s.params['signature'] == Auth.sign([s.params['payload'], s.request.user_agent].join).chomp
    p = JSON.parse(Base64.urlsafe_decode64(s.params['payload']))
    return 403 unless p.key? 'expire'
    return 403 unless p['expire'] > Time.now.to_i

    # build and authorize cookies
    Auth.authorize(p, s.request).each do |cookie, value|
      s.cookies.set(cookie, value: value, expires: Time.now + Auth.cookie_ttl)
    end
    200
  end
end
