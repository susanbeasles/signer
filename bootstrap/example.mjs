// Nulls are deliberately unresolved public commissioning inputs. No live key or credential.
export function exampleInput() {
  return {
    schema: 'signing-control-bootstrap-input/v1',
    accountID: '1a799c6e699d2ef7e87398692ce3ad7b',
    ownerOrigin: 'https://control.vespoli.me',
    source: { repository: 'susanbeasles/signer', repositoryID: null, commit: null, artifactSha256: null },
    onePassword: { accountDomain: null, vaultName: null, vaultID: null, itemName: 'gh-signing-key', itemID: null, serviceAccountID: null },
    github: { login: 'susanbeasles', accountID: '215839550', title: 'signer', publicKey: null },
    runtime: {
      // Public metadata recorded in source-publication-github-identities.json.
      // Inclusion here is a disabled commissioning proposal, not policy approval.
      services: [
        ['ProsRUs', 1412827677], ['personal-control', 1408909065],
        ['backup-control', 1407276404], ['ghcaretaker', 1405513776],
        ['workflow_depot', 1405415683], ['deployer', 1405415291],
        ['repoctl', 1404914851], ['signer', 1416201242],
      ].map(([name, repositoryID]) => ({
        schema: 'signing-control-service/v1', repositoryID, repository: `susanbeasles/${name}`,
        git: { program: '/usr/bin/git', sha256: null, directory: '/run/signing-control/git', authenticated: true, maxObjects: 100000, maxBytes: 8388608 },
        signer: { keyID: null },
      })),
      runtime: {
          schema: 'signing-control-op-agent/v1', opRef: null, publicKey: null, keyID: null, opOrigins: [],
          toolchain: {
            op: { path: '/usr/local/bin/op', sha256: null },
            sshAgent: { path: '/usr/bin/ssh-agent', sha256: null },
            sshAdd: { path: '/usr/bin/ssh-add', sha256: null },
            sshKeygen: { path: '/usr/bin/ssh-keygen', sha256: null },
          },
      },
      platform: { provider: 'cloudflare-containers', imageDigest: null },
    },
  };
}

