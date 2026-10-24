# Security and private inputs

Never commit local/, work/, tools/, contributions/, credentials, context packs,
checker downloads, disassembly, game binaries/images, compiler files or logs.
The ignore rules and privacy check are defense in depth; review the exact staged
file list before publishing. DPAPI blobs are private even though encrypted.

The default listener is loopback-only. External hosting needs an HTTPS proxy and
operator-managed authentication. Host/origin and agent IDs are not authentication.
Only connect trusted contributors: candidate compilation consumes host resources
and processes untrusted source. Use a separate unprivileged account or isolated
host, bounded compiler concurrency and least-privilege service credentials.

Use your own approved contributor account; do not share API keys with agents.
The coordinator owns service mutations. Never bypass quota, image, source,
function-span, compiler or hash checks. Do not replay uncertain mutations.

Report security problems privately to the repository maintainer through GitHub.
Do not include secrets, licensed game content or private checker/context files
in issues. Rotate an exposed credential through its issuer.
