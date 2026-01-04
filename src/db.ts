import pg from "pg";

const { Pool } = pg;

export type DbTx = {
  query: <T = any>(text: string, params?: any[]) => Promise<{ rows: T[] }>;
};

export type Db = DbTx & {
  withTx: <T>(fn: (tx: DbTx) => Promise<T>) => Promise<T>;
  close: () => Promise<void>;
};

// 轻量 DB 封装：避免引入重 ORM，保持 MCP 服务体积小。
export function createDb(databaseUrl: string): Db {
  const pool = new Pool({ connectionString: databaseUrl });

  async function withTx<T>(fn: (tx: DbTx) => Promise<T>): Promise<T> {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const tx: DbTx = {
        query: async (text, params) => {
          const r = await client.query(text, params);
          return { rows: r.rows as any[] };
        },
      };
      const out = await fn(tx);
      await client.query("COMMIT");
      return out;
    } catch (err) {
      try {
        await client.query("ROLLBACK");
      } catch {
        // ignore
      }
      throw err;
    } finally {
      client.release();
    }
  }

  return {
    query: async (text, params) => {
      const r = await pool.query(text, params);
      return { rows: r.rows as any[] };
    },
    withTx,
    close: async () => {
      await pool.end();
    },
  };
}
