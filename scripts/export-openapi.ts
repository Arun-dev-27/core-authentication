import 'reflect-metadata';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { VERSION_NEUTRAL, VersioningType } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { FastifyAdapter } from '@nestjs/platform-fastify';
import { SwaggerModule } from '@nestjs/swagger';
import { loadEnvFiles } from '@config/configuration';
import { AppModule } from '../src/app.module';
import { buildOpenApiConfig } from '../src/bootstrap';

/**
 * Writes the OpenAPI document to docs/openapi.json without connecting to databases.
 *   npm run openapi:export
 */
async function main() {
  loadEnvFiles();
  const app = await NestFactory.create(AppModule, new FastifyAdapter(), { preview: true, logger: false, abortOnError: false });
  // Same versioning as bootstrap.ts so the document lists both /<path> and /v1/<path>.
  app.enableVersioning({ type: VersioningType.URI, defaultVersion: VERSION_NEUTRAL });
  const document = SwaggerModule.createDocument(app, buildOpenApiConfig());
  const out = join(__dirname, '..', 'docs');
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, 'openapi.json'), JSON.stringify(document, null, 2));
  console.log(`wrote docs/openapi.json (${Object.keys(document.paths).length} paths)`);
  await app.close();
}

main().catch((error: unknown) => {
  console.error(error);
  process.exit(1);
});
