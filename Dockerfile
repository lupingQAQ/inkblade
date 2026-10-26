# syntax=docker/dockerfile:1.7
# InkBlade container image.
#
#   docker build -t inkblade:dev .
#   docker run --rm inkblade:dev --help
#   docker run --rm -v inkblade-data:/data inkblade:dev doctor
#
# Design notes
#   * two stages: wheels are built with the repo present, the runtime image only
#     receives the installed wheel (no compiler, no source tree)
#   * runs as uid/gid 10001, never root, no writable system paths
#   * /data is the only writable location (workspace, evidence, reports, users)
#   * HEALTHCHECK validates the entry point plus packaged module data

ARG PYTHON_VERSION=3.12

FROM python:3.12-slim AS wheelbuild

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /src
COPY . /src
RUN python -m pip wheel . --no-deps --wheel-dir /dist \
 && ls -l /dist


FROM python:${PYTHON_VERSION}-slim AS runtime

ARG INKBLADE_VERSION=0.0.0

LABEL org.opencontainers.image.title="InkBlade" \
      org.opencontainers.image.description="Authorized security assessment platform for Kubernetes ML training and inference clusters" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${INKBLADE_VERSION}" \
      org.opencontainers.image.source="https://github.com/inkblade/inkblade"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 10001 inkblade \
 && useradd --uid 10001 --gid 10001 --no-create-home \
      --home-dir /data --shell /usr/sbin/nologin inkblade \
 && mkdir -p /data/evidence /data/reports /data/workspaces \
 && chown -R 10001:10001 /data

COPY --from=wheelbuild /dist/*.whl /tmp/wheels/
RUN python -m pip install --no-cache-dir --no-deps /tmp/wheels/*.whl \
 && rm -rf /tmp/wheels

WORKDIR /data
USER 10001:10001

# 8765 is the web UI / API port when the container is started with
# `ui --host 0.0.0.0`. It is not published in the default CMD.
EXPOSE 8765
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=10s --start-period=25s --retries=3 \
  CMD inkblade module list > /dev/null 2>&1 || exit 1

ENTRYPOINT ["inkblade"]
CMD ["--help"]
