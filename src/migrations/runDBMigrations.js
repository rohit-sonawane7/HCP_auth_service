/* eslint-disable no-console */
const {
  up, database, status, down,
} = require('migrate-mongo');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');

const { setConfig } = require('./dbMigrationsConfig');
const argv = yargs(hideBin(process.argv)).argv;

/**
 * @param db
 * @param client
 */
async function migrationUp(db, client) {
  const migrated = await up(db, client);
  if (!migrated.length) {
    const migrationStatus = await status(db);
    migrationStatus.forEach(({
      fileName, appliedAt,
    }) => {
      console.log(fileName, ':', appliedAt);
    });
    console.log('No pending migrations');

    return process.exit();
  }
  migrated.forEach((fileName) => {
    console.log('Migrated:', fileName);
  });

  return console.log('All migrations applied');
}

/**
 * @param db
 * @param client
 */
async function migrationDown(db, client) {
  const migratedDown = await down(db, client);
  if (!migratedDown.length) {
    console.log('No available migrations to down');

    return process.exit();
  }
  migratedDown.forEach((fileName) => {
    console.log('Migrated Down:', fileName);
  });

  return console.log('All migrations applied');
}

/**
 *
 */
async function runDBMigrations() {
  setConfig();

  try {
    const {
      db, client,
    } = await database.connect();
    if (argv.up) {
      await migrationUp(db, client);
    } else if (argv.down) {
      await migrationDown(db, client);
    } else {
      throw new Error('Uknown flag.');
    }

    return process.exit();
  } catch (err) {
    console.error(err);

    return process.exit(1);
  }
}

runDBMigrations();
