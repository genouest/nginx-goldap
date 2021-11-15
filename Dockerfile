FROM golang:alpine

RUN apk add musl-dev
RUN mkdir /lib64 && ln -s /lib/libc.musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2

WORKDIR /root
COPY .git /root/
COPY go.* /root/
RUN go mod download
COPY *.go /root/
RUN go build -o nginx-goldap


FROM alpine:latest
WORKDIR /root
RUN mkdir /lib64 && ln -s /lib/libc.musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2
COPY --from=0 /root/nginx-goldap /usr/bin/
EXPOSE 9999
ENTRYPOINT ["/usr/bin/nginx-goldap"]



