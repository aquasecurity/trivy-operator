FROM alpine:20230901
RUN apk update && apk add --upgrade libcrypto3 libssl3

RUN adduser -u 10000 -D -g '' trivyoperator trivyoperator

COPY trivy-operator /usr/local/bin/trivy-operator

USER 10000

ENTRYPOINT ["trivy-operator"]
