import { PasswordHasher } from './password-hasher';

describe('PasswordHasher (scrypt)', () => {
  const hasher = new PasswordHasher();

  it('hashes with a random salt and verifies', async () => {
    const a = await hasher.hash('i');
    const b = await hasher.hash('i');
    expect(a).toMatch(/^scrypt\$ln=15,r=8,p=1\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$/);
    expect(a).not.toBe(b);
    await expect(hasher.verify('i', a)).resolves.toBe(true);
    await expect(hasher.verify('I', a)).resolves.toBe(false);
    await expect(hasher.verify('', a)).resolves.toBe(false);
  });

  it('never embeds the plaintext', async () => {
    const encoded = await hasher.hash('SuperSecret-Plaintext');
    expect(encoded).not.toContain('SuperSecret');
  });

  it('returns false (not throw) for missing or malformed hashes', async () => {
    await expect(hasher.verify('x', null)).resolves.toBe(false);
    await expect(hasher.verify('x', 'plaintext')).resolves.toBe(false);
    await expect(hasher.verify('x', 'scrypt$ln=2,r=8,p=1$AAAA$AAAA')).resolves.toBe(false);
  });

  it('flags weaker parameters for rehash', async () => {
    expect(hasher.needsRehash(await hasher.hash('x'))).toBe(false);
    expect(hasher.needsRehash('scrypt$ln=14,r=8,p=1$AAAA$AAAA')).toBe(true);
  });
});
