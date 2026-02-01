FROM python:3.14-slim
# Minimal oqs-mock image used for integration tests
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates git && rm -rf /var/lib/apt/lists/*
# Install liboqs or use a lightweight mock server
RUN pip install flask
COPY oqs-mock-server.py /oqs-mock-server.py
CMD ["python", "/oqs-mock-server.py"]
