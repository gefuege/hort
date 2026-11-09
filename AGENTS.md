# Agents

## Release

GitHub Actions handle everything except npm on tag push: GoReleaser (binaries, Homebrew, Scoop, version from the tag) and the Docker image `ghcr.io/gefuege/hort`.

npm publish is manual — Sebastian runs it locally after tagging:

```bash
git tag v<version> && git push --tags
# wait for GoReleaser to finish, then:
cd npm && npm version <version> --no-git-tag-version && npm publish --access=public
```

Package: `@s16e/hort` on npmjs.org.

Do not automate npm publish via CI — token rotation overhead is not worth it for the release frequency.
