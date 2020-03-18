FROM ubuntu:bionic AS chainspec-builder

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

# Build node.
RUN cargo build --release


# Final stage. Copy the node executable and the script
FROM ubuntu:bionic

RUN apt -y update && apt install -y --no-install-recommends curl

WORKDIR /dock-testnet

COPY --from=chainspec-builder /dock-testnet/target/release/dock-testnet .

# This script will be run to start the node and add the keys
COPY ./run_node.sh .
# The following script will run the full node and insert key. Make it executable
RUN chmod +x ./run_node.sh

# expose node ports
EXPOSE 30333 9933 9944

# The sciprt will be given command line arguments as: <secret phrase> <aura public key> <grandpa public key>
ENTRYPOINT ["./run_node.sh"]
CMD []
