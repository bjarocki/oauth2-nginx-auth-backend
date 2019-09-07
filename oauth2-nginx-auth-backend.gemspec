# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'ops/oauth2/version'

Gem::Specification.new do |spec|
  spec.name          = 'oauth2-nginx-auth-backend'
  spec.version       = Ops::Oauth2::VERSION
  spec.authors       = ['Bartek Jarocki']
  spec.email         = ['bartek@smatly.com']

  spec.summary       = 'oauth2 nginx auth_request backend'
  spec.homepage      = 'https://github.com/bjarocki/oauth2-nginx-auth-backend'

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = 'bin'
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_development_dependency 'bundler', '~> 1.14'
  spec.add_development_dependency 'rubocop', '~> 0.49'

  spec.add_runtime_dependency 'email', '~> 0.1.0'
  spec.add_runtime_dependency 'httparty', '~> 0.15'
  spec.add_runtime_dependency 'sinatra', '~> 2.0'
  spec.add_runtime_dependency 'sinatra-contrib', '~> 2.0'
  spec.add_runtime_dependency 'sinatra-logger', '>= 0.2.6'
end
