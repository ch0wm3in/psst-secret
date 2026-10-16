FROM node:24-slim AS frontend

WORKDIR /app/theme/static_src
COPY theme/static_src/package*.json ./
RUN npm ci
COPY theme/static_src ./
COPY templates/ /app/templates/
COPY static/js/ /app/static/js/
COPY whispers/ /app/whispers/
RUN npm run build

FROM python:3.14-slim-trixie
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Dependency for compilemessages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gettext

# Environment variables for UV configuration
ENV UV_NO_DEV=1
ENV UV_LOCKED=1
ENV UV_COMPILE_BYTECODE=1
ENV UV_NO_CACHE=1

ENV GRANIAN_HOST=0.0.0.0
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync
ENV PATH="/app/.venv/bin:$PATH"
ARG APP_VERSION=dev
ENV APP_VERSION=${APP_VERSION}
COPY . .
COPY --from=frontend /app/theme/static /app/theme/static
RUN ["chmod", "+x", "/app/entrypoint"]
EXPOSE 8000
ENTRYPOINT [ "/app/entrypoint" ]