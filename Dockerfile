FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# BPF objects are pre-generated (internal/capture/pgtrace_x86_bpfel.o); run
# `make generate` after editing bpf/pgtrace.bpf.c.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /pgtrace-agent ./cmd/pgtrace-agent

FROM debian:bookworm-slim
COPY --from=build /pgtrace-agent /usr/local/bin/pgtrace-agent
ENTRYPOINT ["/usr/local/bin/pgtrace-agent"]
