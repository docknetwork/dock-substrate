FROM ubuntu:bionic as chainspec-builder

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

# setup rust nightly channel
RUN rustup install nightly

# install wasm toolchain for substrate
RUN rustup target add wasm32-unknown-unknown --toolchain nightly

# show backtraces
ENV RUST_BACKTRACE 1

#compiler ENV
ENV CC gcc
ENV CXX g++

# Copy code to build directory
COPY . /dock-testnet

# The following script will run the full node and insert key. Make it executable
RUN chmod +x ./run_node.sh

# Build node.
RUN cargo build --release

# expose node ports
EXPOSE 30333 9933 9944

# The sciprt will be given command line arguments as: <secret phrase> <aura public key> <grandpa public key>
ENTRYPOINT ["./run_node.sh"]
CMD []
