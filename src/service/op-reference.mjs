// Pure public-reference parser shared by the bootstrap UI and installed runtime.
// Field/section IDs are not uniformly UUIDs (the SSH field ID is private_key).
// Commissioning must compare these explicit tokens with public item metadata.
export function parseSSHKeyReference(reference) {
  const match = typeof reference === 'string' && /^op:\/\/([a-z2-7]{26})\/([a-z2-7]{26})\/([A-Za-z0-9_][A-Za-z0-9_-]{0,63})(?:\/([A-Za-z0-9_][A-Za-z0-9_-]{0,63}))?\?ssh-format=openssh$/.exec(reference);
  if (!match) throw new Error('Invalid installed SSH key reference');
  return { vaultID: match[1], itemID: match[2], sectionID: match[4] ? match[3] : null, fieldID: match[4] ?? match[3] };
}
