import type { DataSource, EntityManager } from 'typeorm';

export type Queryable = DataSource | EntityManager;

export async function queryOne<T>(db: Queryable, sql: string, params: unknown[] = []): Promise<T | null> {
  const rows = (await db.query(sql, params)) as T[];
  return rows[0] ?? null;
}

export async function queryMany<T>(db: Queryable, sql: string, params: unknown[] = []): Promise<T[]> {
  return (await db.query(sql, params)) as T[];
}
