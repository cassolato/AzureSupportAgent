FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Node.js (for `npx @azure/mcp`) and the Azure CLI (for local DefaultAzureCredential
# via mounted ~/.azure). Kept in one layer to slim the image.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends curl ca-certificates gnupg libicu76 \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && curl -sL https://aka.ms/InstallAzureCLIDeb | bash \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the project metadata and package source needed to build/install the
# wheel (pyproject declares packages = ["app"]), then install. Done before the
# full COPY so the dependency layer is cached unless these inputs change.
COPY pyproject.toml ./
COPY app ./app
RUN pip install --upgrade pip && pip install .

COPY . .

# Drop root — see the note in the root Dockerfile. The app spawns the Azure CLI and MCP
# servers, so it must not run as UID 0.
RUN useradd --system --create-home --uid 10001 --shell /usr/sbin/nologin app \
    && mkdir -p /app/.data /home/app/.azure /home/app/.npm \
    && chown -R app:app /app /home/app
ENV HOME=/home/app \
    NPM_CONFIG_CACHE=/home/app/.npm
USER app

EXPOSE 8000

CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
