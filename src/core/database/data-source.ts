import 'reflect-metadata';
import { DataSource } from 'typeorm';
import { loadEnv, loadEnvFiles } from '@config/configuration';
import { buildDataSourceOptions } from './data-source-options';

// Used by the TypeORM CLI (migrations) and standalone scripts.
loadEnvFiles();

export default new DataSource(buildDataSourceOptions(loadEnv()));
