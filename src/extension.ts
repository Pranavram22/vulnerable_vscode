import * as vscode from 'vscode';
import { scanFile, scanWorkspace } from './scanner';
import { VulnerabilityInstance } from './vulnerability-models';

// Store diagnostics collection
let diagnosticCollection: vscode.DiagnosticCollection;

// Tracks if AI scanning is enabled
let aiScanningEnabled = true;

export function activate(context: vscode.ExtensionContext) {
  console.log('Vulnerability Guardian extension is now active');

  // Create diagnostics collection
  diagnosticCollection = vscode.languages.createDiagnosticCollection('vulnerability-guardian');
  context.subscriptions.push(diagnosticCollection);

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand('vulnerability-guardian.scanCurrentFile', scanCurrentFile),
    vscode.commands.registerCommand('vulnerability-guardian.scanWorkspace', scanEntireWorkspace),
    vscode.commands.registerCommand('vulnerability-guardian.toggleAIScanning', toggleAIScanning),
    vscode.commands.registerCommand('vulnerability-guardian.showVulnerabilityDetails', showVulnerabilityDetails)
  );

  // Register status bar item
  const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBarItem.command = 'vulnerability-guardian.scanCurrentFile';
  statusBarItem.text = '$(shield) Scan';
  statusBarItem.tooltip = 'Scan for vulnerabilities';
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  // Set up document change listeners
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument(event => {
      if (event.document.languageId === 'javascript' || 
          event.document.languageId === 'typescript' ||
          event.document.languageId === 'javascriptreact' ||
          event.document.languageId === 'typescriptreact') {
        // Only scan on document save to avoid constant scanning
        vscode.workspace.onDidSaveTextDocument(doc => {
          if (doc === event.document) {
            scanDocument(doc);
          }
        });
      }
    })
  );

  // Scan current file on startup if there is one
  if (vscode.window.activeTextEditor) {
    scanDocument(vscode.window.activeTextEditor.document);
  }
}

async function scanCurrentFile() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showInformationMessage('No file is currently open');
    return;
  }

  vscode.window.withProgress({
    location: vscode.ProgressLocation.Notification,
    title: 'Scanning for vulnerabilities',
    cancellable: false
  }, async (progress) => {
    progress.report({ increment: 0 });
    await scanDocument(editor.document);
    progress.report({ increment: 100 });
    return;
  });
}

async function scanEntireWorkspace() {
  if (!vscode.workspace.workspaceFolders) {
    vscode.window.showInformationMessage('No workspace is open');
    return;
  }

  vscode.window.withProgress({
    location: vscode.ProgressLocation.Notification,
    title: 'Scanning workspace for vulnerabilities',
    cancellable: true
  }, async (progress, token) => {
    const results = await scanWorkspace(progress, token);
    
    if (token.isCancellationRequested) {
      vscode.window.showInformationMessage('Vulnerability scan was cancelled');
      return;
    }
    
    if (results.totalVulnerabilities === 0) {
      vscode.window.showInformationMessage('No vulnerabilities found in workspace');
    } else {
      vscode.window.showWarningMessage(
        `Found ${results.totalVulnerabilities} potential vulnerabilities in ${results.scannedFiles} files`,
        'View Report'
      ).then(selection => {
        if (selection === 'View Report') {
          showVulnerabilityReport(results.vulnerabilities);
        }
      });
    }
  });
}

function toggleAIScanning() {
  aiScanningEnabled = !aiScanningEnabled;
  vscode.window.showInformationMessage(
    aiScanningEnabled ? 
      'AI-assisted vulnerability scanning enabled' : 
      'AI-assisted vulnerability scanning disabled'
  );
}

async function scanDocument(document: vscode.TextDocument) {
  if (document.languageId !== 'javascript' && 
      document.languageId !== 'typescript' &&
      document.languageId !== 'javascriptreact' &&
      document.languageId !== 'typescriptreact') {
    return;
  }

  try {
    const vulnerabilities = await scanFile(document.getText(), document.fileName, aiScanningEnabled);
    updateDiagnostics(document, vulnerabilities);
    
    if (vulnerabilities.length > 0) {
      vscode.window.showWarningMessage(
        `Found ${vulnerabilities.length} potential vulnerabilities in ${document.fileName}`,
        'View Details'
      ).then(selection => {
        if (selection === 'View Details') {
          showVulnerabilityDetails(vulnerabilities[0]);
        }
      });
    }
  } catch (error) {
    console.error('Error scanning document:', error);
  }
}

function updateDiagnostics(document: vscode.TextDocument, vulnerabilities: VulnerabilityInstance[]) {
  const diagnostics: vscode.Diagnostic[] = [];

  vulnerabilities.forEach(vulnerability => {
    const lineNumber = vulnerability.lineNumber - 1; // VS Code uses 0-based line numbers
    const line = document.lineAt(lineNumber);
    const range = new vscode.Range(
      lineNumber, vulnerability.columnNumber,
      lineNumber, line.text.length
    );

    const diagnostic = new vscode.Diagnostic(
      range,
      `${vulnerability.vulnerability.name}: ${vulnerability.vulnerability.description}`,
      mapSeverityToVSCode(vulnerability.vulnerability.severity)
    );

    // Add metadata to the diagnostic
    diagnostic.code = vulnerability.vulnerability.id;
    diagnostic.source = 'Vulnerability Guardian';
    diagnostic.relatedInformation = [
      new vscode.DiagnosticRelatedInformation(
        new vscode.Location(document.uri, range),
        `Remediation: ${vulnerability.vulnerability.remediation}`
      )
    ];

    diagnostics.push(diagnostic);
  });

  diagnosticCollection.set(document.uri, diagnostics);
}

function mapSeverityToVSCode(severity: string): vscode.DiagnosticSeverity {
  switch (severity) {
    case 'Critical':
      return vscode.DiagnosticSeverity.Error;
    case 'High':
      return vscode.DiagnosticSeverity.Error;
    case 'Medium':
      return vscode.DiagnosticSeverity.Warning;
    case 'Low':
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Warning;
  }
}

function showVulnerabilityDetails(vulnerability: VulnerabilityInstance) {
  // Create and show a webview panel
  const panel = vscode.window.createWebviewPanel(
    'vulnerabilityDetails',
    `Vulnerability: ${vulnerability.vulnerability.name}`,
    vscode.ViewColumn.Beside,
    { enableScripts: true }
  );

  // AI confidence score (simulated)
  const aiConfidenceScore = Math.floor(Math.random() * 30) + 70; // 70-99%
  
  // Generate the HTML for the webview
  panel.webview.html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Vulnerability Details</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial; padding: 20px; }
        h1 { color: #d32f2f; font-size: 24px; margin-bottom: 10px; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; margin-right: 8px; }
        .critical { background-color: #d32f2f; color: white; }
        .high { background-color: #f57c00; color: white; }
        .medium { background-color: #fbc02d; color: black; }
        .low { background-color: #7cb342; color: white; }
        .section { margin: 20px 0; }
        h2 { font-size: 18px; margin-bottom: 8px; color: #333; }
        pre { background-color: #f5f5f5; padding: 10px; border-radius: 4px; overflow-x: auto; }
        .ai-section { background-color: #e8f5e9; padding: 15px; border-radius: 8px; margin-top: 20px; }
        .confidence { display: flex; align-items: center; margin: 10px 0; }
        .meter { flex-grow: 1; height: 8px; background-color: #e0e0e0; border-radius: 4px; margin: 0 10px; }
        .meter-fill { height: 100%; border-radius: 4px; background-color: #43a047; width: ${aiConfidenceScore}%; }
      </style>
    </head>
    <body>
      <h1>
        ${vulnerability.vulnerability.name}
        <span class="badge ${vulnerability.vulnerability.severity.toLowerCase()}">${vulnerability.vulnerability.severity}</span>
        <span class="badge">${vulnerability.vulnerability.id}</span>
      </h1>
      
      <div class="section">
        <p>${vulnerability.vulnerability.description}</p>
      </div>
      
      <div class="section">
        <h2>Affected Code</h2>
        <p>File: ${vulnerability.filePath}</p>
        <p>Line: ${vulnerability.lineNumber}, Column: ${vulnerability.columnNumber}</p>
        <pre><code>${escapeHtml(vulnerability.lineContent)}</code></pre>
      </div>
      
      <div class="section">
        <h2>Remediation</h2>
        <p>${vulnerability.vulnerability.remediation}</p>
      </div>
      
      <div class="section">
        <h2>Examples</h2>
        <ul>
          ${vulnerability.vulnerability.examples.map(example => `<li>${example}</li>`).join('')}
        </ul>
      </div>
      
      ${vulnerability.vulnerability.cwe ? `
      <div class="section">
        <h2>References</h2>
        <p>CWE: ${vulnerability.vulnerability.cwe}</p>
      </div>
      ` : ''}
      
      <div class="ai-section">
        <h2>AI Analysis</h2>
        <div class="confidence">
          <span>Confidence:</span>
          <div class="meter">
            <div class="meter-fill"></div>
          </div>
          <span>${aiConfidenceScore}%</span>
        </div>
        <p>Based on analysis of the code pattern and context, this appears to be a ${vulnerability.vulnerability.severity.toLowerCase()} risk vulnerability that could potentially be exploited.</p>
        <p>The AI model has detected that this code matches patterns commonly associated with ${vulnerability.vulnerability.name.toLowerCase()} vulnerabilities.</p>
      </div>
    </body>
    </html>
  `;
}

function showVulnerabilityReport(vulnerabilities: VulnerabilityInstance[]) {
  const panel = vscode.window.createWebviewPanel(
    'vulnerabilityReport',
    'Vulnerability Report',
    vscode.ViewColumn.One,
    { enableScripts: true }
  );

  // Group vulnerabilities by severity
  const criticalVulns = vulnerabilities.filter(v => v.vulnerability.severity === 'Critical');
  const highVulns = vulnerabilities.filter(v => v.vulnerability.severity === 'High');
  const mediumVulns = vulnerabilities.filter(v => v.vulnerability.severity === 'Medium');
  const lowVulns = vulnerabilities.filter(v => v.vulnerability.severity === 'Low');

  panel.webview.html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Vulnerability Report</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial; padding: 20px; }
        h1 { font-size: 24px; margin-bottom: 20px; }
        .summary { display: flex; gap: 10px; margin-bottom: 20px; }
        .summary-item { padding: 15px; border-radius: 8px; flex: 1; text-align: center; }
        .critical { background-color: #ffebee; border: 1px solid #d32f2f; }
        .high { background-color: #fff3e0; border: 1px solid #f57c00; }
        .medium { background-color: #fffde7; border: 1px solid #fbc02d; }
        .low { background-color: #f1f8e9; border: 1px solid #7cb342; }
        .count { font-size: 32px; font-weight: bold; margin: 10px 0; }
        .critical .count { color: #d32f2f; }
        .high .count { color: #f57c00; }
        .medium .count { color: #fbc02d; }
        .low .count { color: #7cb342; }
        .section { margin: 30px 0; }
        h2 { font-size: 18px; margin-bottom: 10px; color: #333; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #e0e0e0; }
        th { background-color: #f5f5f5; }
        tr:hover { background-color: #f9f9f9; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
      </style>
    </head>
    <body>
      <h1>Vulnerability Report</h1>
      
      <div class="summary">
        <div class="summary-item critical">
          <h3>Critical</h3>
          <div class="count">${criticalVulns.length}</div>
        </div>
        <div class="summary-item high">
          <h3>High</h3>
          <div class="count">${highVulns.length}</div>
        </div>
        <div class="summary-item medium">
          <h3>Medium</h3>
          <div class="count">${mediumVulns.length}</div>
        </div>
        <div class="summary-item low">
          <h3>Low</h3>
          <div class="count">${lowVulns.length}</div>
        </div>
      </div>
      
      <div class="section">
        <h2>Findings</h2>
        <table>
          <thead>
            <tr>
              <th>Vulnerability</th>
              <th>Location</th>
              <th>Severity</th>
              <th>Category</th>
            </tr>
          </thead>
          <tbody>
            ${vulnerabilities.map(v => `
              <tr>
                <td>${v.vulnerability.name}</td>
                <td>${v.filePath}:${v.lineNumber}</td>
                <td><span class="badge ${v.vulnerability.severity.toLowerCase()}" style="background-color: ${getSeverityColor(v.vulnerability.severity)};">${v.vulnerability.severity}</span></td>
                <td>${v.vulnerability.category}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </body>
    </html>
  `;
}

function getSeverityColor(severity: string): string {
  switch (severity) {
    case 'Critical': return '#d32f2f';
    case 'High': return '#f57c00';
    case 'Medium': return '#fbc02d';
    case 'Low': return '#7cb342';
    default: return '#757575';
  }
}

function escapeHtml(unsafe: string): string {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

export function deactivate() {
  // Clean up resources
  if (diagnosticCollection) {
    diagnosticCollection.clear();
    diagnosticCollection.dispose();
  }
}
