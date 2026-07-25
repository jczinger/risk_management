# VMS Stage 1 — single image, three roles (web / worker / beat) chosen by command.
FROM python:3.13-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# libpq for psycopg; pango/cairo/harfbuzz for WeasyPrint PDF export; postgresql-client for the
# backup script and pg_dump-based acceptance checks.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
        postgresql-client \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libharfbuzz0b \
        libcairo2 \
        libgdk-pixbuf-2.0-0 \
        shared-mime-info \
        fonts-dejavu-core \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Build deps are installed, used, then dropped in one layer to keep the image small.
COPY requirements.txt ./
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libpq-dev \
    && pip install -r requirements.txt \
    && apt-get purge -y --auto-remove build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . .

# Run as an unprivileged user; the media volume is chowned to it in compose.
RUN groupadd --gid 1000 vms \
    && useradd --uid 1000 --gid vms --create-home vms \
    && mkdir -p /app/media /app/staticfiles \
    && chown -R vms:vms /app

USER vms

# Collect static files at BUILD time, not at deploy time.
#
# They are part of the build artifact: every container then has an identical
# /app/staticfiles including the manifest that CompressedManifestStaticFilesStorage
# needs. Running collectstatic from the one-shot migrate container instead would write
# it into that container's own filesystem, and `web` would start with no manifest and
# fail on the first page it tried to render.
#
# The env values below exist only to satisfy settings validation during the build; they
# are never used at runtime, when the real values arrive from the environment.
RUN DJANGO_SETTINGS_MODULE=config.settings.prod \
    DJANGO_SECRET_KEY="build-time-placeholder-not-a-runtime-secret-0123456789abcdef" \
    PLATFORM_MASTER_KEY="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" \
    ALLOWED_HOSTS="localhost" \
    python manage.py collectstatic --noinput --clear \
    && test -f /app/staticfiles/staticfiles.json

EXPOSE 8000

CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000"]
