#!/bin/bash
set -e; RUN=$1; SEED=$2; CLS=$3; TRAIN=45; TEST=70; NVAR=24
OUT=results/$RUN; mkdir -p $OUT; rm -f $OUT/*
docker rm -f sensor victim sink backup loadgen attacker >/dev/null 2>&1 || true
docker run -d --name sink --network lab -v $PWD/results/$RUN:/out orcid-sink >/dev/null
docker run -d --name victim --network lab orcid-victim >/dev/null
docker run -d --name backup --network lab orcid-backup >/dev/null
sleep 3
SINK_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' sink)
cgid(){ docker run --rm --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:ro orcid-sensor stat -c %i /sys/fs/cgroup/docker/$(docker inspect -f '{{.Id}}' $1); }
echo "{\"victim\":$(cgid victim),\"backup\":$(cgid backup),\"sink\":$(cgid sink),\"sink_ip\":\"$SINK_IP\",\"cls\":\"$CLS\"}" > $OUT/identities.json
docker run -d --name sensor --privileged --pid=host --cgroupns=host -e BPFTRACE_MAX_STRLEN=200 -v /sys:/sys -v $PWD/sensor:/s -v $PWD/results/$RUN:/out orcid-sensor sh -c 'bpftrace /s/trace.bt >/out/events.tsv 2>/out/sensor.err' >/dev/null
sleep 6
docker run -d --name loadgen --network lab -v $PWD/attacks:/a orcid-victim python3 /a/loadgen.py $SEED $((TRAIN+TEST+20)) >/dev/null
sleep $TRAIN
if [ "$CLS" = control ]; then sleep $TEST; echo -n > $OUT/campaign.jsonl; else
  docker run --name attacker --network lab -v $PWD/attacks:/a orcid-victim python3 /a/evade.py $SINK_IP $NVAR $SEED $CLS > $OUT/campaign.jsonl 2>$OUT/campaign.err || true; fi
sleep 3; docker rm -f sensor loadgen attacker >/dev/null 2>&1 || true
echo "[$RUN cls=$CLS] events=$(wc -l < $OUT/events.tsv) variants=$(wc -l < $OUT/campaign.jsonl)"
