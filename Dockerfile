FROM python:3.12-slim-trixie

LABEL org.opencontainers.image.title="Docker Who" \
      org.opencontainers.image.description="User attribution for Docker processes" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# The observer needs bpftrace with fentry/fexit and BTF support.
RUN apt-get update \
 && apt-get install -y --no-install-recommends bpftrace \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY docker_who ./docker_who
RUN pip install --no-cache-dir .

ENTRYPOINT ["docker-who"]
CMD ["--help"]
