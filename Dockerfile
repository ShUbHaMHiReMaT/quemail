# QuMail receiver container.
#
# Runs as an unprivileged user with a read-only root filesystem. No keys, no
# credentials and no .env are baked into the image: mount the keystore at
# runtime and inject secrets through the environment.

FROM python:3.12-slim AS base

# Do not write .pyc files, do not buffer logs (so they reach the log driver).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Dependencies first so the layer caches independently of application changes.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml README.md ./
COPY qumail ./qumail
RUN pip install --no-cache-dir --no-deps .

# Unprivileged runtime user. /var/lib/qumail is the only writable location and
# is expected to be a mounted volume holding the keystore, contacts and state.
RUN useradd --system --create-home --home-dir /home/qumail --shell /usr/sbin/nologin qumail \
    && mkdir -p /var/lib/qumail \
    && chown -R qumail:qumail /var/lib/qumail \
    && chmod 700 /var/lib/qumail

ENV QUMAIL_HOME=/var/lib/qumail \
    QUMAIL_KEYSTORE=/var/lib/qumail/keystore.json \
    QUMAIL_CONTACTS=/var/lib/qumail/contacts.json \
    QUMAIL_STATE_DIR=/var/lib/qumail/state \
    QUMAIL_OUTPUT_DIR=/var/lib/qumail/inbox \
    QUMAIL_LOG_FORMAT=json \
    QUMAIL_WEB_HOST=0.0.0.0 \
    QUMAIL_WEB_PORT=8000

USER qumail
VOLUME ["/var/lib/qumail"]
EXPOSE 8000

# Render polls /healthz itself; this covers plain `docker run`.
HEALTHCHECK --interval=60s --timeout=10s --start-period=20s --retries=3 \
    CMD python -c "import os,urllib.request;\
urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT','8000'),timeout=5)"

ENTRYPOINT ["qumail"]

# The web inbox. Override with `receive` for a headless CLI-only daemon.
CMD ["web", "--include-read"]
