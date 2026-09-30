import { createPool } from 'mysql2/promise';

export async function openDatabase() {
  const pool = createPool({
    host: process.env.MYSQL_HOST || '127.0.0.1', port: Number(process.env.MYSQL_PORT || 3306),
    user: process.env.MYSQL_USER || 'pennywise', password: process.env.MYSQL_PASSWORD,
    database: process.env.MYSQL_DATABASE || 'pennywise', connectionLimit: 5,
    supportBigNumbers: true, charset: 'utf8mb4'
  });
  const db = {
    all: async (sql,args=[]) => (await pool.execute(sql,args))[0],
    run: async (sql,args=[]) => (await pool.execute(sql,args))[0],
    close: () => pool.end()
  };
  db.get = async (sql,args=[]) => (await db.all(sql,args))[0];
  for (const sql of [
    `CREATE TABLE IF NOT EXISTS users (id VARCHAR(36) PRIMARY KEY,name VARCHAR(80) NOT NULL,email VARCHAR(254) NOT NULL UNIQUE,password_hash VARCHAR(256) NOT NULL,is_demo INTEGER NOT NULL DEFAULT 0,created_at BIGINT NOT NULL)`,
    `CREATE TABLE IF NOT EXISTS sessions (token_hash VARCHAR(64) PRIMARY KEY,user_id VARCHAR(36) NOT NULL,expires_at BIGINT NOT NULL,FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)`,
    `CREATE TABLE IF NOT EXISTS transactions (id VARCHAR(36) PRIMARY KEY,user_id VARCHAR(36) NOT NULL,description VARCHAR(120) NOT NULL,type ENUM('income','expense') NOT NULL,category VARCHAR(30) NOT NULL,amount_cents BIGINT NOT NULL CHECK (amount_cents > 0),occurred_on VARCHAR(10) NOT NULL,created_at BIGINT NOT NULL,INDEX transactions_user_date (user_id,occurred_on),FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)`,
    `CREATE TABLE IF NOT EXISTS budgets (user_id VARCHAR(36) NOT NULL,month VARCHAR(7) NOT NULL,amount_cents BIGINT NOT NULL CHECK (amount_cents > 0),PRIMARY KEY (user_id,month),FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)`
  ]) await db.run(sql);
  return db;
}
