import { AsyncLocalStorage } from 'node:async_hooks';

export interface RequestContext {
  correlationId: string;
}

export const requestContext = new AsyncLocalStorage<RequestContext>();

export function currentCorrelationId(): string | undefined {
  return requestContext.getStore()?.correlationId;
}
