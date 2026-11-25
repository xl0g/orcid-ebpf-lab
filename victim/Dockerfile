FROM python:3.12-slim
WORKDIR /app
COPY app.py /app/app.py
COPY templates /app/templates
RUN printf 'DB_PASSWORD=FAKE-db-pass-0000\nAPI_KEY=FAKE-api-key-0000\n' > /app/.env \
 && mkdir -p /root/.aws /var/run/secrets/kubernetes.io/serviceaccount \
 && printf '[default]\naws_access_key_id=AKIAFAKEFAKEFAKE0000\naws_secret_access_key=FAKEFAKEFAKE\n' > /root/.aws/credentials \
 && echo 'eyFAKE.SERVICEACCOUNT.TOKEN' > /var/run/secrets/kubernetes.io/serviceaccount/token
CMD ["python3", "-u", "/app/app.py"]
