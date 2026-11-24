# Nimbus Chain reference engine (nimbus-core v0.18): build, test, and run the benchmarks in a container.
#   docker build -t nimbus-chain .
#   docker run --rm nimbus-chain                  # end-to-end pipeline benchmark
#   docker run --rm nimbus-chain match-bench      # any benchmark binary: hash-bench, lc-bench, journal-bench, ...
FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY nimbus-core/ nimbus-core/
WORKDIR /src/nimbus-core
RUN cargo build --release --locked \
 && mkdir -p /out \
 && for b in pipeline-bench match-bench hash-bench lc-bench journal-bench sig-bench repl-bench tcp-bench \
             recovery-bench certify-bench nimbus-signer; do \
      [ -f target/release/$b ] && cp target/release/$b /out/ || true; \
    done

FROM debian:bookworm-slim
RUN useradd --create-home nimbus
COPY --from=build /out/ /usr/local/bin/
USER nimbus
WORKDIR /home/nimbus
ENV PIPELINE_ORDERS=100000
ENTRYPOINT []
CMD ["pipeline-bench"]
