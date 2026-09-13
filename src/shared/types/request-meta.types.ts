export interface RequestMeta {
  ip: string;
  userAgent?: string;
  origin?: string;
  csrf?: string;
  sessionHandle?: string;
}
