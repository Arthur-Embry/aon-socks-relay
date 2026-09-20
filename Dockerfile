FROM python:3.12-slim
WORKDIR /app
COPY server.py /app/server.py
ENV BIND=0.0.0.0 PORT=1080
EXPOSE 1080/tcp 1080/udp
CMD ["python", "-u", "/app/server.py"]
