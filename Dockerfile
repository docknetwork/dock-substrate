FROM ubuntu:bionic

# The node will be built in this directory
WORKDIR /dock-testnet

RUN apt -y update && \
	apt install -y --no-install-recommends \
	software-properties-common curl git file binutils binutils-dev \
	make cmake ca-certificates g++ zip dpkg-dev python openssl gettext\
	build-essential pkg-config libssl-dev libudev-dev time clang

# install rustup
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y

# rustup directory
ENV PATH /root/.cargo/bin:$PATH

# setup rust nightly and stable channels
RUN rustup install nightly
RUN rustup install stable

# install wasm toolchain for substrate
RUN rustup target add wasm32-unknown-unknown --toolchain nightly

# show backtraces
ENV RUST_BACKTRACE 1

#compiler ENV
ENV CC gcc
ENV CXX g++

# Copy code to build directory
COPY . /dock-testnet

# Build node.
RUN cargo build --release

# expose node ports
EXPOSE 30333 9933 9944

# Run the node
CMD [ "./target/release/dock-testnet", "--dev", "--chain=remdev"]