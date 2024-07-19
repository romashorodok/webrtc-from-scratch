FROM alpine:3.20.1 as examples-builder

RUN apk add --no-cache python3-dev py3-pip
RUN apk add --no-cache gcc musl-dev linux-headers
RUN apk add --no-cache libsrtp-dev openssl-dev

RUN pip install poetry==1.8.3 --break-system-packages

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    POETRY_NO_INTERACTION=1 \
    POETRY_HOME=/opt/poetry \
    POETRY_CACHE_DIR=/opt/.cache \
    POETRY_VIRTUALENVS_IN_PROJECT=true

WORKDIR /app/examples
COPY examples/pyproject.toml examples/poetry.toml examples/poetry.lock ./
RUN touch README.md

RUN --mount=type=bind,source=./src,target=../src \
    --mount=type=bind,source=./pyproject.toml,target=../pyproject.toml \
    --mount=type=bind,source=./poetry.toml,target=../poetry.toml \
    --mount=type=bind,source=./poetry.lock,target=../poetry.lock \
    --mount=type=bind,source=./README.md,target=../README.md \
    poetry install --without dev --no-root

FROM alpine:3.20.1 as examples-runtime
RUN apk add --no-cache python3
RUN apk add --no-cache libsrtp

ENV PATH="/opt/venv/bin:$PATH"

ENV VIRTUAL_ENV=/app/examples/.venv \
    PATH="${VIRTUAL_ENV}/bin:$PATH"

WORKDIR /app

COPY . .

COPY --from=examples-builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}

WORKDIR /app/examples

CMD [ "sh", "-c", "source .venv/bin/activate && uvicorn examples.examples_ws:app --host 0.0.0.0 --port 9000" ]

