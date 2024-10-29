# Build stage
FROM python:3.12-alpine as builder

# Install build dependencies
RUN apk add --no-cache \
    build-base \
    python3-dev \
    libffi-dev

WORKDIR /app

# Install uv
RUN pip install uv

# Copy dependency files
COPY pyproject.toml uv.lock ./

# Export dependencies and compile wheels
RUN uv pip compile pyproject.toml --refresh --extra test -o requirements.txt \
    && uv pip wheel --no-deps --wheel-dir /app/wheels -r requirements.txt

# Final stage
FROM python:3.12-alpine

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache libffi

# Install uv
RUN pip install uv

# Copy wheels and install dependencies
COPY --from=builder /app/wheels /wheels
COPY pyproject.toml ./

# Install dependencies from wheels
RUN uv pip install --no-cache /wheels/*.whl \
    && rm -rf /wheels

# Copy source code
COPY core/ ./core/
COPY main.py ./

# Run tests by default
CMD ["python", "main.py"]