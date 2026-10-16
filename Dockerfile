ARG VERSION=v5.8.0
FROM certbot/certbot:$VERSION

LABEL org.opencontainers.image.source="https://github.com/Responsible-User/certbot-dns-godaddy-v3"
LABEL maintainer="11071031+Responsible-User@users.noreply.github.com"
ENV PYTHONIOENCODING="UTF-8"

COPY . src/certbot-dns-godaddy

RUN pip install -U pip
RUN pip install --no-cache-dir src/certbot-dns-godaddy

ENTRYPOINT ["/usr/bin/env"]
