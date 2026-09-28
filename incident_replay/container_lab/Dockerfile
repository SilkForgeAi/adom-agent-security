FROM python:3.12-slim

WORKDIR /app
COPY adom /app/adom
COPY incident_replay/container_lab/service.py /lab/service.py
COPY incident_replay/container_lab/broker.py /lab/broker.py
COPY incident_replay/container_lab/agent.py /lab/agent.py
ENV PYTHONPATH=/app
WORKDIR /lab

RUN chmod -R a+rX /app/adom /lab && useradd --uid 10001 --create-home labuser
USER 10001:10001

ENTRYPOINT ["python", "-B"]
