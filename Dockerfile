FROM python:3.11-slim

LABEL maintainer="Dominik Blain <dominik@qreativelab.io>"
LABEL description="COBALT — Z3-verified C/C++ security scanner"
LABEL version="2.1.0"

# System deps: clang compiler + shared lib (needed for header resolution + libclang ctypes)
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang-14 \
    libclang1-14 \
    && rm -rf /var/lib/apt/lists/*

# Python deps — libclang 14 bundles its own .so; z3-solver provides Z3 bindings
RUN pip install --no-cache-dir \
    z3-solver==4.13.0.0 \
    libclang==14.0.6

# Ensure libclang.so is discoverable by ctypes fallback search
RUN ln -sf /usr/lib/x86_64-linux-gnu/libclang-14.so.1 /usr/lib/libclang.so 2>/dev/null || \
    ln -sf /usr/lib/llvm-14/lib/libclang.so.1 /usr/lib/libclang.so 2>/dev/null || true

# Copy scanner
COPY cobalt_c_scanner.py /cobalt/cobalt_c_scanner.py
COPY entrypoint.sh /cobalt/entrypoint.sh

RUN chmod +x /cobalt/entrypoint.sh

WORKDIR /github/workspace

ENTRYPOINT ["/cobalt/entrypoint.sh"]
