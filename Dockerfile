FROM python:3.14.5-alpine3.22
ARG NETADMIN_BUILD_VERSION=unknown
ENV NETADMIN_BUILD_VERSION=${NETADMIN_BUILD_VERSION}
RUN apk add --no-cache bind-tools freeradius-utils libstdc++
WORKDIR /app
COPY pyproject.toml /app/
COPY netadmin /app/netadmin
RUN pip install --no-cache-dir --only-binary :all: . \
    && addgroup -S netadmin && adduser -S -G netadmin netadmin \
    && mkdir -p /data && chown netadmin:netadmin /data
USER netadmin
EXPOSE 8099
CMD ["gunicorn", "--bind", "0.0.0.0:8099", "--workers", "1", "--timeout", "90", "--access-logfile", "-", "netadmin.wsgi:app"]
