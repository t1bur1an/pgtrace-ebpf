FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# BPF objects are pre-generated (internal/capture/pgtrace_x86_bpfel.o); run
# `make generate` after editing bpf/pgtrace.bpf.c.
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /pgtrace-agent ./cmd/pgtrace-agent

# Static binary: no libc or shell needed. The root variant, since the agent
# loads BPF programs; includes CA certificates for an https OTLP endpoint.
FROM gcr.io/distroless/static-debian12
LABEL org.opencontainers.image.title="pgtrace-agent" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/t1bur1an/pgtrace-ebpf"
COPY LICENSE /LICENSE
COPY --from=build /pgtrace-agent /usr/local/bin/pgtrace-agent
# Soft memory cap: the GC works harder before the agent passes it.
# Override with -e GOMEMLIMIT=… (or add GOGC=… to trade memory for GC CPU).
ENV GOMEMLIMIT=768MiB
ENTRYPOINT ["/usr/local/bin/pgtrace-agent"]
