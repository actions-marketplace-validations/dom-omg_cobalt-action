FROM ubuntu:22.04

LABEL maintainer="Dominik Blain <dominik@qreativelab.io>"
LABEL description="COBALT — Z3-verified C/C++ security scanner"
LABEL version="2.1.0"

ENV DEBIAN_FRONTEND=noninteractive

# System deps: Python 3 + clang-14 + shared lib
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    clang-14 \
    libclang1-14 \
    && rm -rf /var/lib/apt/lists/*

# Python deps
RUN pip3 install --no-cache-dir \
    z3-solver==4.13.0.0 \
    libclang==14.0.6

# Symlink: libclang Python binding ctypes search fallback (arch-agnostic)
RUN find /usr/lib -name "libclang-14.so.1" | head -1 | xargs -I{} ln -sf {} /usr/lib/libclang.so


# Copy scanner
COPY cobalt_c_scanner.py /cobalt/cobalt_c_scanner.py
COPY entrypoint.sh /cobalt/entrypoint.sh

RUN chmod +x /cobalt/entrypoint.sh

WORKDIR /github/workspace

ENTRYPOINT ["/cobalt/entrypoint.sh"]
