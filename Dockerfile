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

# Temporarily commented out.
#ARG secret_phrase
#ARG aura_public_key
#ARG grandpa_public_key

# Run the node
# CMD [ "./target/release/dock-testnet", "--dev", "--chain=remdev", "--rpc-external", "--ws-external", "--rpc-cors=all"]

# Adding sleep to make sure that the node has started
RUN ./target/release/dock-testnet --dev --chain=remdev --rpc-external --ws-external --rpc-cors=all & \
    sleep 15 && \
    curl http://localhost:9933 -H "Content-Type:application/json;charset=utf-8" -d '{"jsonrpc":"2.0","id":1,"method":"author_insertKey","params": ["aura","lumber beach surround echo dry staff juice angry whip network nothing about","0xa2ea4182316306ed30794a80cc3e9cbfb3379b95330ee9c4a25746537dfe726e"]}' && \
    curl http://localhost:9933 -H "Content-Type:application/json;charset=utf-8" -d '{"jsonrpc":"2.0","id":1,"method":"author_insertKey","params": ["gran","lumber beach surround echo dry staff juice angry whip network nothing about","0x19fb9c563305c632440accf6ae5a355fcb756e40bd25bf58cf7884cb513a6b5d"]}'

# Stupid hack to run the node
CMD [ "./target/release/dock-testnet", "--dev", "--chain=remdev", "--rpc-external", "--ws-external", "--rpc-cors=all"]