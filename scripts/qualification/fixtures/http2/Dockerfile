FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

# The dated Debian Snapshot keeps the dependency index and nghttp2 client
# available after bookworm's moving mirrors retire this security revision.
# APT verifies the archive's signed Release metadata; the exact nghttp2
# binaries are fetched from the immutable pool and checked before install.
RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20240929T143658Z bookworm main' > /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends ca-certificates wget libev4 libjansson4 libjemalloc2 libxml2 zlib1g \
    && wget -q -O /tmp/libnghttp2-14.deb 'https://snapshot.debian.org/archive/debian/20240929T143658Z/pool/main/n/nghttp2/libnghttp2-14_1.52.0-1+deb12u2_amd64.deb' \
    && wget -q -O /tmp/nghttp2-client.deb 'https://snapshot.debian.org/archive/debian/20240929T143658Z/pool/main/n/nghttp2/nghttp2-client_1.52.0-1+deb12u2_amd64.deb' \
    && echo 'dbe3eb8c831e654ac7d5cf045d605d53fd763e8ebc238607c25f301996103bb9  /tmp/libnghttp2-14.deb' | sha256sum -c - \
    && echo '194c57f19645300ce991cdbfe15d35edc0097bc78a7478f420d5bf39c5b7f788  /tmp/nghttp2-client.deb' | sha256sum -c - \
    && dpkg --install /tmp/libnghttp2-14.deb /tmp/nghttp2-client.deb \
    && rm -f /tmp/libnghttp2-14.deb /tmp/nghttp2-client.deb \
    && rm -rf /var/lib/apt/lists/*
