FROM alpine:3.20

RUN apk add --no-cache curl

COPY smoke-test.sh smoke-test.sh

USER nobody

CMD ["sh", "smoke-test.sh", "http://app:3000"]
