FROM python:3.12.4-alpine as examples-ws

RUN apk add --no-cache g++ musl-dev gcompat libstdc++ libffi-dev
RUN apk add --no-cache libsrtp-dev openssl-dev

RUN python3 -m venv --system-site-packages /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app

COPY ./requirements.txt /app/requirements.txt

RUN --mount=type=cache,target=/root/.cache \
    pip install -Ur /app/requirements.txt

COPY . .

