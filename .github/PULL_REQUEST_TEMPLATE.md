## Summary

<!-- What does this change and why? Link the issue it addresses. -->

Closes #

## Type of change

- [ ] New scenario
- [ ] Detection fix or improvement
- [ ] Hardened workflow fix
- [ ] Verification change
- [ ] Documentation
- [ ] CI / repository tooling

## Evidence

<!-- Paste the output that shows this works. For detection or verification
     changes this is required: show the scanner flagging the vulnerable
     workflow AND clearing the hardened one. -->

```
```

## Checklist

- [ ] `shellcheck detections/*/detect.sh verify/*/verify.sh` passes
- [ ] `verify/*/verify.sh static` passes for every scenario
- [ ] Third-party actions are pinned to a full commit SHA, verified against the upstream tag
- [ ] `permissions:` declared explicitly and scoped per job
- [ ] No real credentials, tokens, or personal data included
- [ ] Attack code only targets the `turla-lab-targets` organization
- [ ] Docs and `CHANGELOG.md` updated where relevant
- [ ] Limitations are stated honestly in the relevant README
