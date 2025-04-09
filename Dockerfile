FROM python:3.9-slim
RUN apt-get update && apt-get install -y tcpdump iputils-ping procps && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY qnx_monitor.py /app/
COPY config /app/config
RUN chmod +x /app/qnx_monitor.py

ENTRYPOINT ["python3", "/app/qnx_monitor.py"]

CMD ["--ip-file", "/app/config/ips.txt", "--all-ports"]
