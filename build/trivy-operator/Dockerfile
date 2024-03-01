FROM alpine:3.19.1

RUN adduser -u 10000 -D -g '' trivyoperator trivyoperator

COPY trivy-operator /usr/local/bin/trivy-operator

USER 10000

ENTRYPOINT ["trivy-operator"]
