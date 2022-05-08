FROM alpine:3.15

RUN adduser -u 10000 -D -g '' trivyoperator trivyoperator

COPY starboard /usr/local/bin/starboard

USER starboard

ENTRYPOINT ["starboard"]
