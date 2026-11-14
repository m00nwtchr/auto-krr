# syntax=docker/dockerfile:1
FROM ghcr.io/astral-sh/uv:python3.13-alpine AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_NO_DEV=1 \
    UV_PYTHON_DOWNLOADS=0

WORKDIR /app

RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project --no-editable

COPY . /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-editable

FROM python:3.13-alpine AS runtime

RUN apk add --no-cache ca-certificates git helm \
    && case "$(apk --print-arch)" in \
        x86_64) flate_arch=amd64; flate_sha256=05d3c79447647e95329aa45c7035e7ebac3a120942972e78819deadc3bf0afeb ;; \
        aarch64) flate_arch=arm64; flate_sha256=345b8b679de439343003097b79aabec7d070c05e70eeca5c413193ba97aa368f ;; \
        *) echo "unsupported architecture: $(apk --print-arch)" >&2; exit 1 ;; \
    esac \
    && wget -q -O /tmp/flate.tar.gz "https://github.com/home-operations/flate/releases/download/v0.7.3/flate_0.7.3_linux_${flate_arch}.tar.gz" \
    && echo "${flate_sha256}  /tmp/flate.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/flate.tar.gz -C /usr/local/bin flate \
    && chmod +x /usr/local/bin/flate \
    && rm /tmp/flate.tar.gz \
    && addgroup -g 1001 app \
    && adduser -D -u 1001 -G app -h /app -s /sbin/nologin app

COPY --from=builder --chown=app:app /app/.venv /app/.venv

USER app

ENTRYPOINT ["/app/.venv/bin/auto-krr"]
