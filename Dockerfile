FROM python:3.14-slim-trixie
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

RUN apt-get update && apt-get install -y --no-install-recommends \
    gettext

ENV UV_NO_DEV=1
ENV UV_LOCKED=1
ENV GRANIAN_HOST=0.0.0.0
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync
ENV PATH="/app/.venv/bin:$PATH"
COPY . .
RUN ["chmod", "+x", "/app/entrypoint"]
EXPOSE 8000
ENTRYPOINT [ "/app/entrypoint" ]