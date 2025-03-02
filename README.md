
# Vulnerability Guardian - VS Code Extension

## Overview
Vulnerability Guardian is a powerful VS Code extension that helps developers identify and fix security vulnerabilities in their JavaScript and TypeScript code. By scanning your code for common security issues, this extension helps you build more secure applications before they reach production.

## Features

- **Real-time Vulnerability Detection**: Automatically scan for security issues as you code
- **Security Best Practices**: Identifies common security vulnerabilities based on OWASP Top 10
- **Detailed Explanations**: Get comprehensive information about detected vulnerabilities
- **AI-assisted Scanning**: Advanced pattern recognition for more accurate vulnerability detection
- **Custom Severity Levels**: Vulnerabilities are categorized by severity (Critical, High, Medium, Low)
- **Workspace Scanning**: Scan your entire project for security issues
- **Detailed Reports**: View summary reports of all vulnerabilities in your codebase

## Supported Vulnerability Types

Vulnerability Guardian can detect various types of security issues, including:

- **Broken Access Control**: Unauthorized access to protected resources
- **Cryptographic Failures**: Weak encryption or poor key management
- **Injection Flaws**: SQL, NoSQL, OS, and LDAP injection
- **Insecure Design**: Security issues in the application design
- **Authentication Failures**: Weaknesses in authentication mechanisms

## Installation

1. Open VS Code
2. Go to Extensions (Ctrl+Shift+X)
3. Search for "Vulnerability Guardian"
4. Click Install
5. Reload VS Code

Alternatively, you can install the extension manually:
1. Download the `.vsix` file
2. Open VS Code
3. Go to Extensions (Ctrl+Shift+X)
4. Click the "..." menu and select "Install from VSIX..."
5. Select the downloaded `.vsix` file

## Usage

### Scanning the Current File

- Click the shield icon in the status bar
- Right-click in the editor and select "Vulnerability Guardian: Scan Current File"
- Press F1 and type "Vulnerability Guardian: Scan Current File"

### Scanning the Entire Workspace

- Right-click in the Explorer view and select "Vulnerability Guardian: Scan Workspace"
- Press F1 and type "Vulnerability Guardian: Scan Workspace"

### Understanding the Results

Vulnerabilities are displayed in several ways:
- As diagnostics (squiggly underlines) in your code
- In the Problems panel, grouped by severity
- In detailed report webviews showing all detected issues

### Vulnerability Details

Click on "View Details" when prompted to see comprehensive information about a detected vulnerability:
- Description of the vulnerability
- Severity level
- Affected code
- Recommended remediation steps
- Examples of vulnerable code patterns
- AI confidence score

## Configuration

You can configure the extension in your VS Code settings:

```json
{
  "vulnerabilityGuardian.enableAIScan": true,
  "vulnerabilityGuardian.scanOnSave": true
}
```

### Available Settings

- `vulnerabilityGuardian.enableAIScan`: Enable or disable AI-assisted scanning
- `vulnerabilityGuardian.scanOnSave`: Automatically scan files when saved

## Commands

- `vulnerability-guardian.scanCurrentFile`: Scan the currently open file
- `vulnerability-guardian.scanWorkspace`: Scan all files in the workspace
- `vulnerability-guardian.toggleAIScanning`: Toggle AI-assisted scanning on/off

## Requirements

- VS Code 1.60.0 or higher
- Works with JavaScript, TypeScript, JSX, and TSX files

## Known Issues

- AI scanning is still in beta and may occasionally produce false positives
- Large workspace scanning may take time on slower machines

## Release Notes

### 1.0.0

- Initial release of Vulnerability Guardian
- Support for detecting OWASP Top 10 vulnerabilities
- AI-assisted vulnerability detection
- Detailed vulnerability reports

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This extension is licensed under the MIT License.
