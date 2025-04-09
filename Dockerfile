FROM python:3.9-slim

RUN apt-get update && apt-get install -y \
    tcpdump \
    curl \
    tmux \
    procps \
    net-tools \
    iputils-ping \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY qnx_monitor.py /app/
RUN chmod +x /app/qnx_monitor.py

RUN mkdir -p /app/config

RUN echo '#!/bin/bash\n\
    if [ -z "$TMUX" ]; then\n\
    tmux new-session -d -s qnx_monitor "/app/qnx_monitor.py $@"\n\
    echo "QNX Monitor started in tmux session."\n\
    echo "Connect to the session with: docker exec -it <container_name> tmux attach -t qnx_monitor"\n\
    tail -f /dev/null\n\
    else\n\
    exec /app/qnx_monitor.py "$@"\n\
    fi' > /app/entrypoint.sh && chmod +x /app/entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]
