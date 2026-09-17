import * as iconv from 'iconv-lite';

/**
 * Byte-for-byte TypeScript port of the legacy production `Decrypt(string)`.
 *
 * ─── ORIGINAL C# SOURCE (ground truth - do not "improve") ─────────────────────
 *   public string Decrypt(string passwordString)
 *   {
 *       if (string.IsNullOrEmpty(passwordString) || passwordString.Length % 2 != 0)
 *           return string.Empty;
 *
 *       int halfLength = passwordString.Length / 2;
 *       ReadOnlySpan<char> inputSpan = passwordString.AsSpan();
 *       ReadOnlySpan<char> dpass = inputSpan.Slice(0, halfLength);
 *       ReadOnlySpan<char> rnumbers = inputSpan.Slice(halfLength);
 *       Span<char> result = stackalloc char[halfLength];
 *       Span<byte> dByte = stackalloc byte[1];
 *       Span<byte> rByte = stackalloc byte[1];
 *
 *       for (int i = 0; i < halfLength; i++)
 *       {
 *           _encoding1252.GetBytes(dpass.Slice(i, 1), dByte);
 *           _encoding1252.GetBytes(rnumbers.Slice(i, 1), rByte);
 *           byte dpassChar = dByte[0];
 *           byte rnumberChar = rByte[0];
 *           result[i] = (char)(255 - (dpassChar + rnumberChar));
 *       }
 *       return new string(result);
 *   }
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Porting constraints that are load-bearing:
 *  - `_encoding1252` is Windows-1252; we get each char's single byte via
 *    `iconv-lite` encoding `'win1252'` (index 0 of the returned Buffer).
 *  - Empty or odd-length input returns `''` (no throw), exactly like the original.
 *  - `(char)(255 - (dpassChar + rnumberChar))`: each operand is a byte (0-255),
 *    so the sum reaches 510 and `255 - sum` can be as low as -255. C#'s `char`
 *    is a 16-bit UNSIGNED integer and a cast from a negative int WRAPS modulo
 *    65536 (it does not clamp or throw). e.g. 255 - 400 = -145 -> 65391.
 *    `wrapped = ((raw % 65536) + 65536) % 65536` reproduces that exactly.
 *
 * Validated on 2026-09-13 against the MMS stage database (user 30337752) before use.
 *
 * USAGE CONSTRAINT: used only by CredentialService to compare identity_db users.password with the
 * submitted password at sign-in. The plaintext is never logged, persisted or returned.
 */
export function decrypt(passwordString: string | null | undefined): string {
  if (!passwordString || passwordString.length % 2 !== 0) {
    return '';
  }

  const halfLength = passwordString.length / 2;
  const dpass = passwordString.slice(0, halfLength);
  const rnumbers = passwordString.slice(halfLength);

  let result = '';
  for (let i = 0; i < halfLength; i++) {
    const dpassChar = iconv.encode(dpass[i], 'win1252')[0];
    const rnumberChar = iconv.encode(rnumbers[i], 'win1252')[0];

    const raw = 255 - (dpassChar + rnumberChar);
    const wrapped = ((raw % 65536) + 65536) % 65536;
    result += String.fromCharCode(wrapped);
  }

  return result;
}
