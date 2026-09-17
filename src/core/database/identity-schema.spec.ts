import { getMetadataArgsStorage } from 'typeorm';
import { AUTH_ENTITIES } from './entities';
import { AUTH_TABLES } from './identity-schema';

/** Column names an entity maps, read from its decorators (no database needed). */
function entityColumns(entity: object): string[] {
  const storage = getMetadataArgsStorage();
  return storage.filterColumns(entity as never).map((c) => c.options.name ?? c.propertyName);
}
function entityTable(entity: object): string {
  return storage().filterTables(entity as never)[0].name!;
}
const storage = () => getMetadataArgsStorage();

describe('auth table DDL matches the TypeORM entities', () => {
  it('has exactly one CREATE definition per auth entity, and nothing else', () => {
    expect(AUTH_TABLES.map((t) => t.entity)).toEqual(expect.arrayContaining(AUTH_ENTITIES));
    expect(AUTH_TABLES).toHaveLength(AUTH_ENTITIES.length);
  });

  it.each(AUTH_TABLES.map((t) => [entityTable(t.entity as object), t] as const))('%s: CREATE TABLE declares every entity column', (table, t) => {
    const ddl = t.create[0];
    expect(ddl).toMatch(new RegExp(`^CREATE TABLE IF NOT EXISTS ${table} \\(`));
    for (const column of entityColumns(t.entity as object)) expect(ddl).toMatch(new RegExp(`\\n\\s+${column}\\s`));
  });

  it('only ever creates tables and indexes - never a schema, database, function, trigger, or ALTER / DROP', () => {
    for (const statement of AUTH_TABLES.flatMap((t) => t.create)) {
      expect(statement).toMatch(/^(CREATE TABLE IF NOT EXISTS|CREATE (UNIQUE )?INDEX IF NOT EXISTS) /);
      expect(statement).not.toMatch(/\b(DROP|ALTER|TRUNCATE|CREATE SCHEMA|CREATE DATABASE|CREATE FUNCTION|CREATE TRIGGER)\b/i);
    }
  });
});
