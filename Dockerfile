FROM nginx:alpine

# Copy nginx config
COPY server/nginx.conf /etc/nginx/conf.d/default.conf

# Copy distribution landing page
COPY server/index.html /usr/share/nginx/html/index.html
COPY server/install.html /usr/share/nginx/html/install.html

# Copy PWA app files
COPY pwa/ /usr/share/nginx/html/pwa/

EXPOSE 80 443
