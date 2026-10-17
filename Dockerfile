FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

# WeasyPrint (executive PDF) needs pango; remove this line and the 'pdf' extra if PDF export is not needed.
RUN apt-get update && apt-get install -y --no-install-recommends libpango-1.0-0 libpangoft2-1.0-0 \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml alembic.ini ./
COPY src ./src
COPY migrations ./migrations
RUN pip install ".[pdf]"

# Run as an unprivileged user. No secrets are baked into the image: configuration comes from the environment.
RUN useradd --system --uid 10001 --no-create-home cxdash
USER 10001

EXPOSE 8050
# default = web; compose overrides the command for the worker and migrate services
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8050", "--access-logfile", "-", "cxdash.ui.app:server"]
