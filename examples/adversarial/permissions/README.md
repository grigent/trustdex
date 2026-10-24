# Adversarial permission posture fixtures

These fixtures model a restrictive baseline and a later autonomy expansion for
Claude Code and Codex. Every credential, command argument, path, and hostname is
inert test data. The `.invalid` hostname cannot resolve on the public Internet.

The evaluation asserts that:

- restrictive settings remain reviewable without being described as certified safe
- automatic shell, network, filesystem, and subagent expansion is detected
- permission posture comparison returns `needs-review`
- settings values and path values never appear in inspection, snapshot, or diff output

The fixtures do not authorize security testing against any external system and do
not reproduce a real user configuration.
