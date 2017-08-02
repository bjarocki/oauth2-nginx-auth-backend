FROM ruby:2.4

ENV HOME /opt/app
ENV RUBYLIB=$HOME/lib
WORKDIR $HOME

ADD . $HOME

RUN \
  bundler

CMD ruby bin/ops_oauth2_server.rb
