# Use latest Python slim image
FROM python

# Set working directory
WORKDIR /app

# Install poetry
RUN pip install poetry

# Copy poetry files
COPY pyproject.toml poetry.lock* ./

# Copy source code
COPY rings.py hash.py dilithium.py ./

# Configure poetry to not create virtual environment in container
RUN poetry config virtualenvs.create false

# Install dependencies
RUN poetry install --no-dev

# Run tests by default
CMD ["poetry", "run", "python", "dilithium.py"]