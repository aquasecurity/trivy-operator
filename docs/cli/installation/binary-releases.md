Every [release][release] of Starboard provides binary releases for a variety of operating systems. These
binary versions can be manually downloaded and installed.

1. Download desired [release archive][release] for your platform
2. Unpack it. As an example for macOS platform, run the following command:
   ```
   tar -zxvf starboard_darwin_x86_64.tar.gz
   ```
3. Find the `starboard` binary in the unpacked directory, and move it to its desired destination
   ```
   mv ./starboard /usr/local/bin/starboard
   ```

From there, you should be able to run Starboard CLI commands: `starboard help`

## kubectl plugin

The Starboard CLI is compatible with [kubectl] and is intended as [kubectl plugin], but it's perfectly fine to run it as
a stand-alone executable. If you rename the `starboard` executable to `kubectl-starboard` and if it's in your path, you
can invoke it using `kubectl starboard`.

[release]: https://github.com/aquasecurity/starboard/releases/{{ git.tag }}
[kubectl]: https://kubernetes.io/docs/reference/kubectl
[kubectl plugin]: https://kubernetes.io/docs/tasks/extend-kubectl/kubectl-plugins
