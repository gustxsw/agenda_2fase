const pg = require("pg");
const dotenv = require("dotenv");

dotenv.config();

const pool = new pg.Pool({
  connectionString:
    process.env.DATABASE_URL ||
    "postgresql://neondb_owner:npg_FC9TuaYLdMD8@ep-steep-violet-afyt4sti-pooler.c-2.us-west-2.aws.neon.tech/neondb?sslmode=require&channel_binding=require",
});

module.exports = { pool };