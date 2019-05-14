FROM ruby:2.6

ENV HOME /opt/app
ENV RUBYLIB=$HOME/lib
WORKDIR $HOME

ADD . $HOME

RUN \
  bundler

CMD ruby bin/ops_oauth2_server.rb
