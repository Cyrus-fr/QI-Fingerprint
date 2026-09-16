# QI-Fingerprint pipeline image.
# python:3.11-slim is glibc/manylinux-compatible, so fpylll and fastecdsa install
# from wheels (fpylll) or build cleanly against libgmp (fastecdsa). This is the
# whole reason the pipeline runs in a container instead of native Windows.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app

# Build deps: fastecdsa needs GMP; keep the fpylll build toolchain available as a
# fallback in case a matching manylinux wheel is ever unavailable.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libgmp-dev \
        libmpfr-dev \
        libmpc-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependency layer first, so editing source never triggers a dependency reinstall.
COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

# Package install (entry points / metadata). Source is bind-mounted at run time,
# so --no-deps keeps this layer cheap and the deps layer cached.
COPY . .
RUN pip install -e . --no-deps

CMD ["pytest"]
