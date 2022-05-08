# From Source (Linux, macOS)

Building from source is slightly more work, but is the best way to go if you want to test the latest (pre-release)
version of Starboard.

You must have a working Go environment.

```
git clone --depth 1 --branch {{ git.tag }} git@github.com:aquasecurity/starboard.git
cd starboard
make
```

If required, it will fetch the dependencies and cache them. It will then compile `starboard` and place it in
`bin/starboard`.
