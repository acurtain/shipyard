#!/bin/bash

# Root directory of the repository.
CONTROLLER_ROOT=${BATS_TEST_DIRNAME}/../..
BIN_NAME=controller
LISTEN_PORT=8080
BATS_LOG=.bats.log

if [ -z "$DOCKER_HOST" ]; then
    echo "Error: the env var DOCKER_HOST must be set" >&2
    exit 1
fi

if [ -z "$RETHINKDB_ADDR" ]; then
    echo "Error: the env var RETHINKDB_ADDR must be set" >&2
    exit 1
fi

build_controller() {
    pushd $CONTROLLER_ROOT >/dev/null
    godep go build -o $BIN_NAME
    popd >/dev/null
}

# build binary if needed
if [ ! -e ${CONTROLLER_ROOT}/${BIN_NAME} ]; then
    build_conroller
fi

controller() {
    ${CONTROLLER_ROOT}/${BIN_NAME} -disable-usage-info -listen=:${LISTEN_PORT} "$@"
}

wait_until_reachable() {
 local attempts=0
 local max_attempts=5
  until curl -s http://127.0.0.1:${LISTEN_PORT} || [ $attempts -ge $max_attempts  ]; do
    echo "Attempt to connect to ${HOSTS[$i]} failed for the $((++attempts)) time" >&2
    sleep 1.0
  done
  [[ $attempts -lt $max_attempts  ]] 
}

# start controller in background
start_controller() {
  ${CONTROLLER_ROOT}/${BIN_NAME} -docker $DOCKER_HOST -rethinkdb-addr=$RETHINKDB_ADDR &
  CONTROLLER_PID=$!
  echo "$CONTROLLER_PID" >&2
  wait_until_reachable
}

# stops controller
stop_controller() {
    if [ ! -z "$CONTROLLER_PID" ]; then
        kill $CONTROLLER_PID
    fi
}

# removes all test containers
clean_containers() {
    CONTAINERS="docker ps -a | grep ehazlett/busybox"
    STATUS=$?
    if [ "$STATUS" -eq 0 ]; then
        echo "$CONTAINERS" | awk '{ print $1; }' | xargs docker rm -fv
    fi
}
