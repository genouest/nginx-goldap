# LDAP authenticator for Nginx

Use an auth_request to service proxied to:

* http://host:port just to authenticate user
* http://host:port/group1/group2/..  to also check user is in one of groups

Example nginx conf

    server {
        listen       443 ssl http2;
        listen       [::]:443 ssl http2;
        server_name  myserver.genouest.org;
        root         /usr/share/nginx/html;

        ssl_certificate /etc/letsencrypt/live/genouest.org/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/genouest.org/privkey.pem;
        ssl_trusted_certificate /etc/letsencrypt/live/genouest.org/chain.pem;
        ssl_session_cache shared:SSL:1m;
        ssl_session_timeout  10m;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;

        location / {
            auth_request /auth-proxy;
            error_page 401 =200 /;
            try_files $uri $uri/ =404;
        }

        location = /auth-proxy {
            internal;
            # just check user proxy_pass http://localhost:9999/;
            # check user and user is in groupA or groupB proxy_pass http://localhost:9999/groupA/groupB;
            proxy_pass http://localhost:9999/goadmin;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
        }

        include /etc/nginx/errors.conf;

    }

