uid=$(cat /proc/sys/kernel/random/uuid)
COMPOSE="docker-compose -f docker-compose-test.yml -p $uid"

$COMPOSE down -v -t 0

$COMPOSE build
$COMPOSE run --name $uid honeypot-exporter-test
ret=$(docker wait $uid)
$COMPOSE down -v -t 0
docker network rm $uid-honeypot
exit $ret
