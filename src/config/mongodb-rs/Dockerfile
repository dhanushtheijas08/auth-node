ARG MONGO_VERSION
FROM mongo:${MONGO_VERSION}

EXPOSE 27017

ENTRYPOINT [ "sh", "-c", "\
  mongod --port $MONGO_REPLICA_PORT --replSet rs0 --bind_ip_all & \
  MONGOD_PID=$!; \
  echo 'Waiting for MongoDB to start...'; \
  until mongosh --port $MONGO_REPLICA_PORT --eval 'db.adminCommand({ ping: 1 })' >/dev/null 2>&1; do sleep 1; done; \
  echo 'Initializing replica set...'; \
  mongosh --port $MONGO_REPLICA_PORT --eval \"if (!rs.status().ok) rs.initiate({ _id: 'rs0', members: [{ _id: 0, host: '$MONGO_REPLICA_HOST:$MONGO_REPLICA_PORT' }] });\"; \
  echo 'Checking if root user exists...'; \
  USER_EXISTS=$(mongosh admin --quiet --port $MONGO_REPLICA_PORT --eval \"db.getUser('$MONGO_INITDB_ROOT_USERNAME') ? 'yes' : 'no'\"); \
  if [ \"$USER_EXISTS\" = \"no\" ]; then \
    echo 'Creating root user...'; \
    mongosh admin --port $MONGO_REPLICA_PORT --eval \"db.createUser({ user: '$MONGO_INITDB_ROOT_USERNAME', pwd: '$MONGO_INITDB_ROOT_PASSWORD', roles:[{role:'root', db:'admin'}] });\"; \
  else \
    echo 'Root user already exists. Skipping creation.'; \
  fi; \
  echo 'Replica set + root user ready!'; \
  wait $MONGOD_PID \
"]
