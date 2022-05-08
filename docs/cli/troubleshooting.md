# Troubleshooting the Starboard CLI

Feel free to either [open an issue](https://github.com/aquasecurity/starboard/issues), reach out on [Slack](https://slack.aquasec.com), or post your questions in the [discussion forum.](https://github.com/aquasecurity/starboard/discussions)

## "starboard" cannot be opened because the developer cannot be verified. (macOS)

Since Starboard CLI is not registered with Apple by an identified developer, if you try to run it for the first time
you might get a warning dialog. This doesn't mean that something is wrong with the release binary, rather macOS can't
check whether the binary has been modified or broken since it was released.

![](./../images/troubleshooting/developer-not-verified.png)

To override your security settings and use the Starboard CLI anyway, follow these steps:

1. In the Finder on your Mac, locate the `starboard` binary.
2. Control-click the binary icon, then choose Open from the shortcut menu.
3. Click Open.

   ![](./../images/troubleshooting/control-click-open.png)

   The `starboard` is saved as an exception to your security settings, and you can use it just as you can any registered
   app.

You can also grant an exception for a blocked Starboard release binary by clicking the **Allow Anyway** button in the
**General** pane of **Security & Privacy** preferences. This button is available for about an hour after you try to run the
Starboard CLI command.

To open this pane on your Mac, choose Apple menu > **System Preferences**, click **Security & Privacy**, then click **General**.

![](./../images/troubleshooting/developer-not-verified-remediation.png)
