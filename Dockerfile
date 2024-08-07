FROM ubuntu:jammy AS builder

# The node will be built in this directory
WORKDIR /dock-node

RUN apt -y update && \
  apt install -y --no-install-recommends \
  software-properties-common llvm curl git file binutils binutils-dev \
  make cmake ca-certificates clang g++ zip dpkg-dev openssl gettext \
  build-essential pkg-config libssl-dev libudev-dev time clang

# install rustup
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y

# rustup directory
ENV PATH /root/.cargo/bin:$PATH

ARG stable='stable-2023-03-09'
ARG nightly='nightly-2023-03-09'

# setup rust stable and nightly channels, pinning specific version as newer versions have a regression
RUN rustup install $stable
RUN rustup install $nightly

# install wasm toolchain for substrate
RUN rustup target add wasm32-unknown-unknown --toolchain $nightly

#compiler ENV
ENV CC clang
ENV CXX g++

# Copy code to build directory, instead of only using .dockerignore, we copy elements
# explicitly. This lets us cache build results while iterating on scripts.
COPY runtime runtime
COPY node node
COPY pallets pallets
COPY Cargo.toml .
COPY Cargo.lock .

# Build node.
RUN cargo fetch # cache the result of the fetch in case the build gets interrupted
# Pass the features while building image as `--build-arg features='--features mainnet'` or `--build-arg features='--features testnet'`
ARG features
ARG release

RUN if [ "$release" = "Y" ] ; then \
      echo 'Building in release mode.' ; \
      WASM_BUILD_TOOLCHAIN=$nightly cargo +$stable build --profile=release $features ; \
      mv /dock-node/target/release/dock-node /dock-node/target/; \
    else \
      echo 'Building in production mode.' ; \
      WASM_BUILD_TOOLCHAIN=$nightly cargo +$stable build --profile=production $features ; \
      mv /dock-node/target/production/dock-node /dock-node/target/; \
    fi

# Final stage. Copy the node executable and the script
FROM ubuntu:jammy

WORKDIR /dock-node

COPY --from=builder /dock-node/target/dock-node .

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
