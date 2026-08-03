# Microsoft 365 Agent Package

This directory contains the safe Copilot-facing package assets for Azure Security Posture Agent.

- `openapi.template.yaml`: safe read-only operations only.
- `declarativeAgent.template.json`: declarative agent definition with placeholders.
- `apiPlugin.template.json`: API plugin definition with OAuth placeholders.
- `manifest.template.json`: Microsoft 365 application manifest.
- `color.png` and `outline.png`: package icons.
- `build-package.ps1`: deterministic package builder.
- `dist/`: generated zip output. Only `.gitkeep` is committed.

Build the package with non-secret deployment values only:

```powershell
.\m365-agent\build-package.ps1 -ApiBaseUrl "https://your-api.example.com" -OAuthReferenceId "azure-security-posture-oauth" -TenantIdOrDomain "contoso.onmicrosoft.com" -ContactEmail "security@contoso.com" -OAuthClientId "00000000-0000-0000-0000-000000000000"
```

Upload `dist/azure-security-posture-agent.zip` only after verifying the six expected files, live HTTPS host, and matching tenant OAuth reference.
