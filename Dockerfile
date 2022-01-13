FROM ubuntu:bionic AS builder

# The node will be built in this directory
WORKDIR /dock-node

RUN apt -y update && \
	apt install -y --no-install-recommends \
	software-properties-common curl git file binutils binutils-dev \
	make cmake ca-certificates g++ zip dpkg-dev python openssl gettext\
	build-essential pkg-config libssl-dev libudev-dev time clang

# install rustup
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y

# rustup directory
ENV PATH /root/.cargo/bin:$PATH

# setup rust nightly channel, pinning specific version as newer versions have a regression
RUN rustup install nightly

# set default rust compiler
RUN rustup default nightly

# install wasm toolchain for substrate
RUN rustup target add wasm32-unknown-unknown --toolchain nightly

#compiler ENV
ENV CC gcc
ENV CXX g++

# Copy code to build directory, instead of only using .dockerignore, we copy elements
# explicitly. This lets us cache build results while iterating on scripts.
COPY runtime runtime
COPY node node
COPY pallets pallets
COPY common common
COPY Cargo.toml .
COPY Cargo.lock .

# Build node.
RUN cargo fetch # cache the result of the fetch in case the build gets interrupted
# Pass the features while building image as `--build-arg features='--features mainnet'` or `--build-arg features='--features testnet'`
ARG features
RUN cargo build --release $features

# Final stage. Copy the node executable and the script
FROM debian:stretch-slim

WORKDIR /dock-node

COPY --from=builder /dock-node/target/release/dock-node .

# curl is required for uploading to keystore
# note: `subkey insert` is a potential alternarve to curl
RUN apt -y update \
	&& apt install -y --no-install-recommends curl \
	&& rm -rf /var/lib/apt/lists/*

# might need these for uploads to keystore
COPY scripts scripts

# include official chainspecs
COPY cspec cspec

# expose node ports
EXPOSE 30333 9933 9944

ENV RUST_BACKTRACE 1

ENTRYPOINT ["./dock-node"]
CMD []
