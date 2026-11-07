export class AppError extends Error {
  status: number; code: string; action: string; retryable: boolean;
  constructor(status: number, code: string, message: string, action = 'Check the request and try again.') {
    super(message); this.status=status; this.code=code; this.action=action;
    this.retryable=[429,503].includes(status);
  }
}
export function fail(status: number, code: string, message: string, action?: string): never {
  throw new AppError(status,code,message,action);
}
export function assert(condition: unknown, status: number, code: string, message: string): asserts condition {
  if(!condition) fail(status,code,message);
}
export function object(input: unknown, keys: string[]): Record<string, unknown> {
  assert(input !== null && typeof input==='object' && !Array.isArray(input),422,'INVALID_INPUT','Send a JSON object.');
  const obj=input as Record<string,unknown>;
  assert(Object.keys(obj).every(k=>keys.includes(k)),422,'UNKNOWN_FIELD','The request contains an unsupported field.');
  return obj;
}
export function text(value: unknown, min=1, max=128): string {
  assert(typeof value==='string' && value.length>=min && value.length<=max,422,'INVALID_INPUT','A text field is missing or has an invalid length.');
  return value;
}
export function bool(value: unknown): boolean {
  assert(typeof value==='boolean',422,'INVALID_INPUT','Use true or false, not a text or number value.');
  return value;
}
export function integer(value: unknown, min=1, max=Number.MAX_SAFE_INTEGER): number {
  assert(typeof value==='number' && Number.isSafeInteger(value) && value>=min && value<=max,422,'INVALID_INPUT','Use a valid whole number.');
  return value;
}
