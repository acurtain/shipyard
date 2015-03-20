#!/usr/bin/env bats
load helpers
load helpers_api

TEST_DIR=${CONTROLLER_ROOT}/test/integration

teardown() {
  echo "$BATS_TEST_NAME
----------
$output
----------

" >> ${BATS_LOG}
  api_remove_container
  stop_controller
}

@test "controller: show help" {
  run controller -h
  [ "$status" -eq 2  ]
  [[ ${lines[0]} =~ "Usage of"  ]]
}

@test "controller: api get containers" {
  start_controller
  api_create_container -d @${TEST_DIR}/container_busybox.json
  run api_get_containers
  [ "$status" -eq 0  ]
}

@test "controller: api create container" {
  start_controller
  run api_create_container -d @${TEST_DIR}/container_busybox.json
  [ "$status" -eq 0  ]
}

@test "controller: api inspect container" {
  start_controller
  api_create_container -d @${TEST_DIR}/container_busybox.json
  run api_inspect_container ${CONTAINER_ID}
  [ "$status" -eq 0  ]
}
