#! /bin/bash

echo "Name of migration"
read file_name

node src/migrations/createDBMigration.js --file_name=$file_name
