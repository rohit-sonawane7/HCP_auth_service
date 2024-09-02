/* eslint-disable no-console */
const {
  create,
} = require('migrate-mongo');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const { setConfig } = require('./dbMigrationsConfig');

const argv = yargs(hideBin(process.argv)).argv;

/**
 *
 */
async function createMigration() {
  setConfig();

  try {
    console.log("argv.file_name");
    console.log(argv.file_name);
    
    if (!argv.file_name) {
      throw new Error('No filename provided');
    }
    console.log('filenameInitialized');
    const fileName = await create(argv.file_name);
    console.log('filenameCreated');
    
    console.log('Created:', fileName);

    return process.exit();
  } catch (err) {
    console.error(err);

    return process.exit(1);
  }
}

createMigration();
