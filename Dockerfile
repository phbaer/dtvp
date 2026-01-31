# Build arguments for Python version
ARG PYTHON_VERSION=3.14

# Stage 1: Build the frontend
FROM node:lts-alpine AS frontend-build

WORKDIR /app/frontend

# Copy frontend package files
COPY frontend/package*.json ./

# Install frontend dependencies
RUN npm ci

# Copy frontend source code
COPY frontend/ ./

# Build the frontend for production
RUN npm run build

# Stage 2: Build the backend and include frontend assets
FROM python:${PYTHON_VERSION}-alpine

WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Copy dependency files
COPY pyproject.toml uv.lock ./

# Install dependencies using uv
# --frozen ensures we use the exact versions from uv.lock
# --no-dev excludes development dependencies
RUN uv sync --frozen --no-dev

# Copy application code
COPY *.py start.sh ./
RUN chmod +x start.sh

# Copy the built frontend from the frontend-build stage
COPY --from=frontend-build /app/frontend/dist ./frontend/dist

# Expose the port
EXPOSE 8000

# Run the application using the startup script
CMD ["/app/start.sh"]
