FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Build dependencies for Python packages with native extensions.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        build-essential \
        gcc \
        libc6-dev \
        libjpeg62-turbo-dev \
        zlib1g-dev \
        libffi-dev \
        libcairo2-dev \
        libpango1.0-dev \
        libgdk-pixbuf-2.0-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip install --upgrade pip \
    && pip wheel --wheel-dir /wheels --requirement /tmp/requirements.txt \
    && rm -f /tmp/requirements.txt

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Runtime dependencies only.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        git \
        sudo \
        libjpeg62-turbo \
        zlib1g \
        libffi8 \
        libcairo2 \
        libpango-1.0-0 \
        libgdk-pixbuf-2.0-0 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
COPY --from=builder /wheels /wheels
RUN pip install --no-index --find-links=/wheels --requirement /tmp/requirements.txt \
    && rm -f /tmp/requirements.txt \
    && rm -rf /wheels

COPY ./app /app
COPY ./docker/run.sh /app/run.sh

RUN sed -i 's/\r$//' /app/run.sh \
    && chmod +x /app/run.sh \
    && mkdir -p /app/data

# Commit-specific version metadata must not invalidate dependency layers.
ARG AEROFOIL_VERSION
ENV AEROFOIL_VERSION="${AEROFOIL_VERSION}"

ENTRYPOINT ["/app/run.sh"]
