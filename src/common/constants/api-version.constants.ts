import { VERSION_NEUTRAL } from '@nestjs/common';

/**
 * v1 routes are served at /v1/<path> AND at the unversioned /<path>.
 * The unversioned paths are the published federation contract used by every Business Unit
 * (e.g. /embed/login); they stay bound to v1. A future v2 edge declares `version: '2'` only.
 */
export const API_V1: Array<string | typeof VERSION_NEUTRAL> = ['1', VERSION_NEUTRAL];
