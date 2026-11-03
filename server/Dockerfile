FROM python:3.11-slim

WORKDIR /app

COPY database.py dns_engine.py app.py ./

RUN mkdir -p /app/data

ENV DNSIP_DB_PATH=/app/data/dnsip.db
ENV DNSIP_DNS_PORT=53
ENV DNSIP_HTTP_PORT=8080
ENV DNSIP_BIND_HOST=0.0.0.0

EXPOSE 53/udp
EXPOSE 53/tcp
EXPOSE 8080/tcp

CMD ["python3", "app.py"]
