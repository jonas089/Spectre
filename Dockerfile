# syntax=docker/dockerfile:1.3-labs

FROM alpine:3.6 as alpine
RUN apk add -U --no-cache ca-certificates

FROM rustlang/rust:nightly-slim as builder
ADD . /src
WORKDIR /src
COPY --from=alpine /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
RUN apt-get update -y
RUN apt-get install lsb-release software-properties-common gnupg -y
RUN apt-get install -y build-essential     pkg-config     libssl-dev     curl     wget     git
RUN bash -c "$(wget -O - https://apt.llvm.org/llvm.sh)"
RUN git submodule update --init --recursive
RUN cargo build -r -p spectre-prover

FROM scratch
COPY --from=builder /src/target/release/spectre-prover-cli .
ENTRYPOINT [./spectre-prover-cli rpc --port 3000 --spec testnet]

