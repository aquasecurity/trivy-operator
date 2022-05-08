FROM alpine:3.15

RUN adduser -u 10000 -D -g '' trivyoperator trivyoperator

COPY trivy-operator /usr/local/bin/trivy-operator

USER trivyoperator

ENTRYPOINT ["trivy-operator"]
