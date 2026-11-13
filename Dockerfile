# SPDX-FileCopyrightText: 2024-present Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

FROM golang:1.27.3-bookworm@sha256:dc0963f32053e4bc451d24d87e3892d42d01021b61f093e98eb95c0352bb84b0 AS builder

WORKDIR $GOPATH/src/n3iwf
COPY . .
ARG MAKEFLAGS
RUN make all

FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS n3iwf

# Build arguments for dynamic labels
ARG VERSION=dev
ARG VCS_URL=unknown
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.source="${VCS_URL}" \
    org.opencontainers.image.version="${VERSION}" \
    org.opencontainers.image.created="${BUILD_DATE}" \
    org.opencontainers.image.revision="${VCS_REF}" \
    org.opencontainers.image.url="${VCS_URL}" \
    org.opencontainers.image.title="n3iwf" \
    org.opencontainers.image.description="Aether 5G Core N3IWF Network Function" \
    org.opencontainers.image.authors="Aether SD-Core <dev@lists.aetherproject.org>" \
    org.opencontainers.image.vendor="Aether Project" \
    org.opencontainers.image.licenses="Apache-2.0" \
    org.opencontainers.image.documentation="https://docs.sd-core.aetherproject.org/"

ARG DEBUG_TOOLS

RUN apk add --no-cache bash && \
    if [ "$DEBUG_TOOLS" = "true" ]; then \
        apk add --no-cache vim nano tcpdump strace net-tools curl netcat-openbsd bind-tools; \
    fi

# Run as an unprivileged user
RUN addgroup -S -g 1000 aether && adduser -S -u 1000 -G aether aether

# Copy executable
COPY --chmod=755 --from=builder /go/src/n3iwf/bin/* /usr/local/bin/.

# The non-root user needs file capabilities on the binary:
#   CAP_NET_ADMIN        create the XFRM interface and manage IPsec SAs/policies (netlink)
#   CAP_NET_RAW          GRE listener (ip4:gre) and raw IP socket
#   CAP_NET_BIND_SERVICE bind IKE UDP port 500
# They only take effect if they are in the container's bounding set, so the
# container must still be started with --cap-add NET_ADMIN (docker) or
# securityContext.capabilities.add: [NET_ADMIN] (Kubernetes).
RUN apk add --no-cache libcap-setcap && \
    setcap cap_net_admin,cap_net_raw,cap_net_bind_service=+ep /usr/local/bin/n3iwf && \
    apk del libcap-setcap

USER 1000:1000
