# syntax=docker/dockerfile:1

# ---- builder: install deps, run the test suite, fail the build if it fails ----
FROM python:3.14-slim AS builder
WORKDIR /build

# wkhtmltopdf is needed at test time (reporter tests exercise PDF generation);
# the rest are build headers for cryptography/lxml in case no prebuilt wheel
# exists yet for this Python version.
RUN apt-get update && apt-get install -y --no-install-recommends \
        wget \
        gcc \
        libxml2-dev \
        libxslt1-dev \
        libssl-dev \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install wkhtmltopdf from GitHub releases (removed from Debian Trixie repos)
RUN wget -q https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-3/wkhtmltox_0.12.6.1-3.bookworm_amd64.deb \
    && apt-get update \
    && apt-get install -y --no-install-recommends ./wkhtmltox_0.12.6.1-3.bookworm_amd64.deb \
    && rm wkhtmltox_0.12.6.1-3.bookworm_amd64.deb \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements-dev.txt ./
# Runtime deps go into the shared site-packages tree (copied into the final
# image below); test-only deps (pytest, ruff, mypy, ...) go into a separate
# target dir so they never leave the builder stage.
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir --target=/test-deps -r requirements-dev.txt

COPY . .
ENV PYTHONPATH=/test-deps
RUN python -m pytest

# ---- runtime: minimal image, no compilers, no test tooling, non-root ----
FROM python:3.14-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        wget \
    && wget -q https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-3/wkhtmltox_0.12.6.1-3.bookworm_amd64.deb \
    && apt-get install -y --no-install-recommends ./wkhtmltox_0.12.6.1-3.bookworm_amd64.deb \
    && apt-get purge -y wget \
    && apt-get autoremove -y \
    && rm wkhtmltox_0.12.6.1-3.bookworm_amd64.deb \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 scanner \
    && mkdir -p /app && chown scanner:scanner /app

# Pulls in only what `pip install -r requirements.txt` put under /usr/local
# in the builder stage - no gcc, no dev headers, no pytest/ruff/mypy.
COPY --from=builder /usr/local /usr/local

WORKDIR /app
COPY --chown=scanner:scanner . .

USER scanner

# cert.pem/key.pem/scanner.db/users.db are generated on first run into /app,
# which is owned by the scanner user, so no volume is required for a quick trial
# (docker-compose.yml does mount one anyway, so the API's data survives restarts).
EXPOSE 8000

# Generic sanity check (module imports) rather than service-specific, since this
# same image runs the CLI, the vulnerable target, and the API - docker-compose.yml
# overrides this per-service with a check that matches what's actually listening.
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import enforcer, crawler, database" || exit 1

# No fixed ENTRYPOINT: CMD is the whole command, so it's freely replaceable.
# Default: run the CLI.
CMD ["python", "main.py"]

# To run the API instead, override the command with a full one, e.g.:
#   docker run --rm -p 8000:8000 <image> uvicorn api.app:app --host 0.0.0.0 --port 8000
# or the vulnerable target:
#   docker run --rm -p 5000:5000 <image> python local_target.py
# (docker-compose.yml wires up all three as separate services.)
