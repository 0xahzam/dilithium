# Build stage
FROM python:alpine as builder

# Install build dependencies
RUN apk add --no-cache \
    build-base \
    python3-dev \
    libffi-dev

WORKDIR /app

# Install poetry
RUN pip install poetry

# Copy dependency files
COPY pyproject.toml poetry.lock* ./

# Export dependencies to requirements.txt
RUN poetry export -f requirements.txt --output requirements.txt --without-hashes

# Install dependencies to get wheel files
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /app/wheels -r requirements.txt

# Final stage
FROM python:alpine

WORKDIR /app

# Install poetry in final stage
RUN pip install poetry

# Copy poetry files and wheels
COPY --from=builder /app/wheels /wheels
COPY pyproject.toml poetry.lock* ./

# Install dependencies using poetry
RUN poetry config virtualenvs.create false \
    && poetry install --no-dev \
    && rm -rf /wheels

# Copy source code
COPY rings.py hash.py dilithium.py ./

# Run tests by default
CMD ["poetry", "run", "python", "dilithium.py"]