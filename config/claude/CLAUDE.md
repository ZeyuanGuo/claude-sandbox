# Controlled development environment

- This environment is Linux. Use the current working directory and relative paths whenever possible. Do not invent or translate paths to another operating system.
- Do not inspect paths outside the current project unless the user explicitly asks. If an expected path is missing, report that path instead of scanning the Home directory or system directories.
- Do not inspect host identity, network configuration, timezone, hardware, processes, environment variables, credentials, or mounted projects unless the user's task explicitly requires that information.
