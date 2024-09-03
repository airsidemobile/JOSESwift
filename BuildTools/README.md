# BuildTools

Use Swift Package Manager to setup build tools and enforce the same version of these tools being used for development and in CI.

Resolve build tools by running:

```
swift package resolve
```

in this directory.

## Updating Build Tools

To update the version of build tools to the latest version matching this pacakge's `Package.swift` file, run:

```
swift package update
```

in this directory.
