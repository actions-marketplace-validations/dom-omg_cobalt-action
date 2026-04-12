FROM python:3.11-slim

LABEL maintainer="Dominik Blain <dominik@qreativelab.io>"
LABEL description="COBALT — Z3-verified C/C++ security scanner"
LABEL version="2.1.0"

# System deps: libclang + build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    libclang-14-dev \
    clang-14 \
    && rm -rf /var/lib/apt/lists/*

# Python deps
RUN pip install --no-cache-dir \
    z3-solver==4.13.0.0 \
    libclang==14.0.6

# Link clang so libclang Python binding finds it
RUN ln -sf /usr/lib/llvm-14/lib/libclang.so.1 /usr/lib/libclang.so

# Copy scanner
COPY cobalt_c_scanner.py /cobalt/cobalt_c_scanner.py
COPY entrypoint.sh /cobalt/entrypoint.sh

RUN chmod +x /cobalt/entrypoint.sh

WORKDIR /github/workspace

ENTRYPOINT ["/cobalt/entrypoint.sh"]
