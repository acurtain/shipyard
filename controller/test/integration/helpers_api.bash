#!/bin/bash

BASE_URL=http://127.0.0.1:${LISTEN_PORT}

api_login() {
    TOKEN=`curl -H "Content-type: application/json" -d '{"username":"admin","password":"shipyard"}' -s http://127.0.0.1:${LISTEN_PORT}/auth/login | jq -r '.auth_token'`
}

api_request() {
    api_login
    curl -H "X-Access-Token: admin:$TOKEN" -H "Content-type: application/json" $@ >> $BATS_LOG
}

api_get_containers() {
    api_request ${BASE_URL}/api/containers
}

api_create_container() {
    api_login
    CONTAINER_ID=`curl -H "X-Access-Token: admin:$TOKEN" -H "Content-type: application/json" -XPOST $@ ${BASE_URL}/api/containers | jq -r '.[]'` >> $BATS_LOG
}

api_remove_container() {
    api_request -XDELETE ${BASE_URL}/api/containers/${CONTAINER_ID}
}

api_inspect_container() {
    api_login
    curl -v -H "X-Access-Token: admin:$TOKEN" ${BASE_URL}/api/containers/$1 >> $BATS_LOG
}
