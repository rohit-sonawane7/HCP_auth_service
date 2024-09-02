const {
  config,
} = require('migrate-mongo');

const CHANGELOG_COLLECTION_NAME = 'changelog';
const MIGRATIONS_DIR = 'src/migrations/db-migrations';
const dotenv = require('dotenv');

dotenv.config();
/**
 *
 */
function setConfig() {
  const appConfig = {
    mongodb: {
      url: process.env.MONGO_URI,
      options: { useNewUrlParser: true },
    },
    migrationsDir: MIGRATIONS_DIR,
    changelogCollectionName: CHANGELOG_COLLECTION_NAME,
    useFileHash: false,
  };

  config.set(appConfig);
}

module.exports = {
  setConfig,
};
