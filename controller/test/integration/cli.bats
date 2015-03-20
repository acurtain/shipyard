#!/usr/bin/env bats

load helpers

@test "cli: show help" {
  run controller -h
  [ "$status" -eq 2  ]
  [[ ${lines[0]} =~ "Usage of"  ]]
}

@test "cli: show version" {
  run controller -version
  [ "$status" -eq 0  ]
}

