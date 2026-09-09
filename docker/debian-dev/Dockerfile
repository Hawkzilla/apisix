FROM debian:bookworm-slim AS build

ARG ENABLE_PROXY=false
ARG CODE_PATH

ENV DEBIAN_FRONTEND=noninteractive
ENV ENV_INST_LUADIR=/usr/local/apisix

COPY ${CODE_PATH} /apisix

WORKDIR /apisix

RUN set -x \
    && apt-get update \
    && apt-get install -y \
        make \
        git \
        sudo \
        libyaml-dev \
    && ls -al \
    && make deps \
    && mkdir -p ${ENV_INST_LUADIR} \
    && cp -r deps ${ENV_INST_LUADIR} \
    && make install \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*


FROM debian:bookworm-slim

ARG ENTRYPOINT_PATH=./docker-entrypoint.sh
ARG INSTALL_BROTLI=./install-brotli.sh

ENV DEBIAN_FRONTEND=noninteractive

# 换 USTC 源
RUN apt-get update \
    && apt-get install -y \
        libldap2-dev \
        libyaml-0-2 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /usr/local/apisix/ui

COPY --from=build /usr/local/apisix /usr/local/apisix
COPY --from=build /usr/local/openresty /usr/local/openresty
COPY --from=build /usr/bin/apisix /usr/bin/apisix
COPY --chown=nobody:root ui/ /usr/local/apisix/ui/

COPY ${INSTALL_BROTLI} /install-brotli.sh

RUN chmod +x /install-brotli.sh \
    && cd / \
    && ./install-brotli.sh \
    && rm -rf /install-brotli.sh \
    && chgrp -R 0 /usr/local/apisix \
    && chmod -R g=u /usr/local/apisix

ENV PATH=$PATH:/usr/local/openresty/luajit/bin:/usr/local/openresty/nginx/sbin:/usr/local/openresty/bin

WORKDIR /usr/local/apisix

RUN ln -sf /dev/stdout /usr/local/apisix/logs/access.log \
    && ln -sf /dev/stderr /usr/local/apisix/logs/error.log

EXPOSE 9080 9443

COPY ${ENTRYPOINT_PATH} /docker-entrypoint.sh

RUN chmod +x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["docker-start"]

STOPSIGNAL SIGQUIT
