FROM alpine:3.16.2

RUN adduser -u 10000 -D -g '' trivyoperator trivyoperator

COPY trivy-operator /usr/local/bin/trivy-operator

USER 10000

ENTRYPOINT ["trivy-operator"]
