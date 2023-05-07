FROM debian:bookworm as builder
RUN apt update && apt install -y clang build-essential cmake

COPY . /muparserx
WORKDIR /muparserx
RUN CXX="clang++" CC="clang" CMAKE_CXX_FLAGS="-fsanitize=fuzzer-no-link" CFLAGS="-fsanitize=fuzzer-no-link" cmake . && make
RUN cd fuzz && make

FROM debian:bookworm
COPY --from=builder /muparserx/fuzz .
