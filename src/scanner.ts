import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { 
  Vulnerability, 
  VulnerabilityInstance, 
  vulnerabilities 
} from './vulnerability-models';

// AI-based detection (simulated)
class AIVulnerabilityDetector {
  detect(code: string, filePath: string): VulnerabilityInstance[] {
    // This is a simulated AI detector
    // In a real extension, this would use a trained model or API call
    
    const results: VulnerabilityInstance[] = [];
    
    // Simple simulation of AI detection based on keywords
    const lines = code.split('\n');
    
    // List of suspicious patterns the AI model would look for
    const aiPatterns = [
      { regex: /password\s*=|apiKey\s*=|secret\s*=|token\s*=/i, vulnerability: "credentials-exposure" },
      { regex: /\.innerHTML\s*=|document\.write\(/i, vulnerability: "xss" },
      { regex: /exec\(|eval\(|Function\(/i, vulnerability: "code-injection" },
      { regex: /http:\/\/|ftp:\/\//i, vulnerability: "insecure-protocol" }
    ];
    
    lines.forEach((line, lineIndex) => {
      aiPatterns.forEach(pattern => {
        const match = line.match(pattern.regex);
        if (match) {
          // Find the most appropriate vulnerability from our defined list
          let matchedVuln: Vulnerability | undefined;
          
          switch (pattern.vulnerability) {
            case "credentials-exposure":
              matchedVuln = vulnerabilities.find(v => v.id === "A04:2021") || vulnerabilities[0];
              break;
            case "xss":
              matchedVuln = vulnerabilities.find(v => v.id === "A03:2021") || vulnerabilities[0];
              break;
            case "code-injection":
              matchedVuln = vulnerabilities.find(v => v.id === "A03:2021") || vulnerabilities[0];
              break;
            case "insecure-protocol":
              matchedVuln = vulnerabilities.find(v => v.id === "A02:2021") || vulnerabilities[0];
              break;
            default:
              matchedVuln = vulnerabilities[0];
          }
          
          if (Math.random() > 0.7) { // Add randomness to simulate AI confidence levels
            results.push({
              id: `ai-${matchedVuln.id}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
              vulnerability: matchedVuln,
              filePath,
              lineNumber: lineIndex + 1,
              columnNumber: match.index || 0,
              lineContent: line,
              timestamp: new Date(),
              fixed: false
            });
          }
        }
      });
    });
    
    return results;
  }
}

const aiDetector = new AIVulnerabilityDetector();

export const scanFile = async (
  code: string, 
  filePath: string,
  useAI: boolean = true
): Promise<VulnerabilityInstance[]> => {
  const results: VulnerabilityInstance[] = [];
  const lines = code.split('\n');
  
  // Pattern-based detection
  lines.forEach((line, lineIndex) => {
    vulnerabilities.forEach(vulnerability => {
      vulnerability.patterns.forEach(pattern => {
        const match = line.match(pattern);
        if (match) {
          results.push({
            id: `${vulnerability.id}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            vulnerability,
            filePath,
            lineNumber: lineIndex + 1,
            columnNumber: match.index || 0,
            lineContent: line,
            timestamp: new Date(),
            fixed: false
          });
        }
      });
    });
  });
  
  // AI-based detection
  if (useAI) {
    const aiResults = aiDetector.detect(code, filePath);
    
    // Deduplicate with existing results to avoid showing the same vulnerability twice
    aiResults.forEach(aiResult => {
      // Check if this line already has a vulnerability of the same type
      const isDuplicate = results.some(result => 
        result.lineNumber === aiResult.lineNumber && 
        result.vulnerability.id === aiResult.vulnerability.id
      );
      
      if (!isDuplicate) {
        results.push(aiResult);
      }
    });
  }
  
  return results;
};

export async function scanWorkspace(
  progress: vscode.Progress<{ increment: number, message?: string }>,
  token: vscode.CancellationToken
) {
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders) {
    return { vulnerabilities: [], scannedFiles: 0, totalVulnerabilities: 0 };
  }

  const jsFiles: string[] = [];
  const allVulnerabilities: VulnerabilityInstance[] = [];
  let scannedFiles = 0;
  
  // Find all JavaScript/TypeScript files
  for (const folder of workspaceFolders) {
    await findJsFiles(folder.uri.fsPath, jsFiles);
  }
  
  const totalFiles = jsFiles.length;
  
  // Scan each file
  for (let i = 0; i < totalFiles; i++) {
    if (token.isCancellationRequested) {
      break;
    }
    
    const file = jsFiles[i];
    const content = await readFile(file);
    
    progress.report({ 
      increment: (100 / totalFiles),
      message: `Scanning ${i + 1}/${totalFiles}: ${path.basename(file)}`
    });
    
    const vulnerabilities = await scanFile(content, file);
    allVulnerabilities.push(...vulnerabilities);
    scannedFiles++;
  }
  
  return {
    vulnerabilities: allVulnerabilities,
    scannedFiles,
    totalVulnerabilities: allVulnerabilities.length
  };
}

async function findJsFiles(dir: string, fileList: string[]) {
  const files = fs.readdirSync(dir);
  
  for (const file of files) {
    const filePath = path.join(dir, file);
    const stat = fs.statSync(filePath);
    
    if (stat.isDirectory() && !file.startsWith('node_modules') && !file.startsWith('.')) {
      await findJsFiles(filePath, fileList);
    } else if (
      stat.isFile() && 
      (file.endsWith('.js') || 
       file.endsWith('.ts') || 
       file.endsWith('.jsx') || 
       file.endsWith('.tsx'))
    ) {
      fileList.push(filePath);
    }
  }
}

function readFile(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    fs.readFile(filePath, 'utf8', (err, data) => {
      if (err) {
        reject(err);
      } else {
        resolve(data);
      }
    });
  });
}
