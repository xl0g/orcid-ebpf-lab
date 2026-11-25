FROM python:3.12-slim
RUN mkdir -p /root/.aws /data && printf '[default]\naws_access_key_id=AKIAFAKEBACKUP0000\n' > /root/.aws/credentials && for i in $(seq 1 20); do head -c 2048 /dev/urandom > /data/f$i; done
COPY backup.sh /backup.sh
CMD ["sh", "/backup.sh"]
