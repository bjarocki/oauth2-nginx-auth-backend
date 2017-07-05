# Nginx Configuration

### /etc/nginx/oauth2-auth.conf
```
auth_request /oauth2/verify;
error_page 401 = https://auth.example.com/oauth2/sign_in;
auth_request_set $auth_cookie $upstream_http_set_cookie;
add_header Set-Cookie $auth_cookie;

```

### /etc/nginx/oauth2-location.conf
```
location /oauth2/ {
  proxy_method     GET;
  proxy_pass       http://127.0.0.1:3000;
  proxy_set_header Content-Length "";
  proxy_set_header Host                    $host;
  proxy_set_header X-Real-IP               $remote_addr;
  proxy_set_header X-Scheme                $scheme;
  proxy_set_header X-Auth-Request-Redirect $scheme://$server_name$request_uri;
}

```
