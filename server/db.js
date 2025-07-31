import pg from "pg";
import dotenv from "dotenv";

dotenv.config();

export const pool = new pg.Pool({
  connectionString:
    process.env.DATABASE_URL ||
    "postgresql://neondb_owner:npg_FC9TuaYLdMD8@ep-steep-violet-afyt4sti-pooler.c-2.us-west-2.aws.neon.tech/neondb?sslmode=require&channel_binding=require",
});
