# syntax=docker/dockerfile:1.3-labs

FROM alpine:3.6 as alpine
RUN apk add -U --no-cache ca-certificates

FROM debian:stable-slim as builder
ENV PATH=/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/u>
ENV CARGO_HOME=/root/.cargo
ADD . /src
WORKDIR /src
COPY --from=alpine /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
RUN <<-EOF
apt-get update -y
apt-get install lsb-release software-properties-common gnupg -y
apt-get install -y build-essential     pkg-config     libssl-dev     curl     wget     git
bash -c "$(wget -O - https://apt.llvm.org/llvm.sh)"
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
git submodule update --init --recursive
cargo build -r -p spectre-prover
EOF

FROM scratch
COPY --from=builder /src/target/release/spectre-prover-cli .
ENTRYPOINT [./spectre-prover-cli rpc --port 3000 --spec testnet]
