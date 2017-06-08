#!/bin/sh

# assign variables here if you don't want them to show in bash history (such as password)
USERNAME=
PASSWORD=
HOST=
REALM=
IGNORE_SSL=false

while [ "$#" -gt 0 ]
do
    case "$1" in
      --username)
          USERNAME=$2
          ;;
      --password)
          PASSWORD=$2 
          ;;
      --host)
          HOST=$2
          ;;
      --realm)
          REALM=$2
          ;;
      --ignore_ssl)
          IGNORE_SSL=true
          ;;
      *)
          FILE=$1
          ;;
    esac
    shift
done

# get the bearer token for the auth header to make admin rest calls
export TOKEN=$(curl -v \
  -d "client_id=admin-cli" \
  -d "username=${USERNAME}" \
  --data-urlencode "password=${PASSWORD}" \
  -d "grant_type=password" \
  "${HOST}/auth/realms/master/protocol/openid-connect/token" \
  | jq -r '.access_token')

# for each User call the curl create user endpoint
jq -c -r ".users[] | ." ${FILE} | while read i; do
curl -v -H "Content-Type: application/json" \
 -H "Authorization: bearer ${TOKEN}" \
 -d "$i" \
 "${HOST}/auth/admin/realms/${REALM}/users"
done
