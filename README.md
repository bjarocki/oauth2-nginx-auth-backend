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

### /etc/oauth2/oauth2.conf example
```
{
  "cookie_domain": ".devops.dance",
  "cookie_name_permissions": "DDIntranetPermissions",
  "cookie_name_redirect": "DDIntranetRedirect",
  "cookie_name_signature": "DDIntranetSignature",
  "cookie_ttl": 86400,
  "default_redirect_page": "https://oauth.devops.dance/",
  "google_oauth_client_id": "XXXXXXXXXXXXX-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.apps.googleusercontent.com",
  "google_oauth_client_secret": "XXXXXXXXXXXXXXXXXXXXXXXX",
  "google_oauth_redirect_url": "https://oauth.devops.dance/oauth2/google/authorize",
  "google_whitelisted_domains": [
    "smatly.com"
  ],
  "google_whitelisted_emails": [],
  "oauth_server_url": "https://oauth.devops.dance/",
  "oauth_shared_secret": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  "slack_oauth_client_id": "XXXXXXXXXXXXXXXXXXXXXXXXX",
  "slack_oauth_client_secret": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  "slack_oauth_redirect_url": "https://oauth.devops.dance/oauth2/slack/authorize",
  "slack_whitelisted_domains": [
    "devops-dance"
  ]
}
```
