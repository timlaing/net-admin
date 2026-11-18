ARG BUILD_FROM
FROM ${BUILD_FROM}
ARG BUILD_VERSION=unknown
ENV NETADMIN_BUILD_VERSION=${BUILD_VERSION}
RUN apk add --no-cache bind-tools freeradius-utils
WORKDIR /app
COPY pyproject.toml /app/
COPY netadmin /app/netadmin
RUN pip install --no-cache-dir --only-binary :all: .
COPY home-assistant/netadmin/run.sh /run.sh
RUN chmod 755 /run.sh
CMD ["/run.sh"]
