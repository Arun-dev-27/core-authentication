export const CLIENT_ID_PATTERN = /^[a-z0-9][a-z0-9-]{2,63}$/;

export const SESSION_HANDLE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export const TRANSACTION_ID_PATTERN = /^[A-Za-z0-9._~-]{6,128}$/;
export const STATE_PATTERN = /^[\x21-\x7E]{8,512}$/;
