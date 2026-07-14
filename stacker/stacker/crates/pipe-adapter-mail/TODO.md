# pipe-adapter-mail TODO

## Future enhancements

- Add durable POP3/IMAP cursor persistence so mailbox polling survives worker restarts without replaying already-processed messages.
- Add explicit replay/reset semantics for mailbox sources so operators can intentionally reprocess a message range when needed.
- Add bounded polling controls in adapter config, including max messages per poll, max body size, and max attachment metadata extraction.
- Add richer mailbox state handling for IMAP, including configurable search criteria beyond `UNSEEN` and explicit `\Seen`/ack behavior.
- Add safer POP3 progression semantics, including optional delete/keep behavior after successful downstream trigger delivery.
- Add multipart attachment metadata improvements, including content-id and inline attachment handling.
- Add adapter-level metrics and structured diagnostics for connect, login, fetch, parse, and delivery outcomes without logging secrets or message bodies.
- Add fixture-driven tests for live protocol edge cases such as malformed MIME, empty mailboxes, duplicate UIDL/UID values, and partial TLS/auth failures.
