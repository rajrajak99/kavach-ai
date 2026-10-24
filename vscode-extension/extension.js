const vscode = require('vscode');

// --- SURGICAL RULES ENGINE (Zero-Noise) ---
const RULES = {
    python: [
        {
            pattern: /(aws_secret_access_key|aws_access_key_id|api_key|apikey|secret_key|auth_token|token|github_token)\s*=\s*["']([^\s"']{16,})["']/i,
            category: "Hardcoded Secret / API Key",
            cwe: "CWE-798",
            severity: vscode.DiagnosticSeverity.Error,
            fix: (line, indent) => line.replace(/=\s*["'][^"'\s]+["']/, '= os.environ.get("SECRET_KEY", "")')
        },
        {
            pattern: /os\.system\s*\(\s*f["'].*?\{.*?\}["']\s*\)/i,
            category: "Command Injection via os.system",
            cwe: "CWE-78",
            severity: vscode.DiagnosticSeverity.Error,
            fix: (line, indent) => `${indent}# Prevent command injection with discrete argument array\n${indent}subprocess.run(["command", safe_argument], check=True)`
        },
        {
            pattern: /(?:SELECT|INSERT|UPDATE|DELETE).*?\{.*?\}/i,
            category: "Raw SQL Injection via f-string",
            cwe: "CWE-89",
            severity: vscode.DiagnosticSeverity.Error,
            fix: (line, indent) => `${indent}# Use parameterized query\n${indent}cursor.execute("SELECT * FROM table WHERE id = %s", (safe_param,))`
        },
        {
            pattern: /([a-zA-Z_]\w*\s*=\s*open\s*\([^)]+\))/i,
            category: "Unmanaged File Descriptor Leak",
            cwe: "CWE-775",
            severity: vscode.DiagnosticSeverity.Warning,
            fix: (line, indent) => {
                const m = line.match(/([a-zA-Z_]\w*)\s*=\s*open\s*\((.*?)\)/);
                if (m) {
                    return `${indent}with open(${m[2]}) as ${m[1]}:`;
                }
                return `${indent}with open(...) as f:`;
            }
        }
    ],
    javascript: [
        {
            pattern: /(?:const|let|var)\s+([a-zA-Z0-9_$]*(?:key|secret|token|auth|password))\s*=\s*["']([^\s"']{16,})["']/i,
            category: "Hardcoded Credential in JavaScript",
            cwe: "CWE-798",
            severity: vscode.DiagnosticSeverity.Error,
            fix: (line, indent) => line.replace(/=\s*["'][^"'\s]+["']/, '= process.env.API_KEY || ""')
        },
        {
            pattern: /child_process\.(?:exec|execSync)\s*\(\s*`.*?`\s*\)/i,
            category: "Arbitrary Command Injection in Node.js",
            cwe: "CWE-78",
            severity: vscode.DiagnosticSeverity.Error,
            fix: (line, indent) => `${indent}// Prevent shell injection by avoiding shell: true\n${indent}child_process.execFile('command', [safeArg], (err, res) => {});`
        },
        {
            pattern: /eval\s*\(/i,
            category: "Critical Arbitrary Code Execution (eval)",
            cwe: "CWE-95",
            severity: vscode.DiagnosticSeverity.Error,
            fix: (line, indent) => `${indent}// Replace eval with safe JSON parser or strict validator\n${indent}const parsedData = JSON.parse(safePayload);`
        }
    ],
    cpp: [
        {
            pattern: /strcpy\s*\(\s*([a-zA-Z0-9_]+)\s*,\s*([a-zA-Z0-9_]+)\s*\)/i,
            category: "Unbounded Buffer Copy (Buffer Overflow)",
            cwe: "CWE-120",
            severity: vscode.DiagnosticSeverity.Error,
            fix: (line, indent) => {
                const m = line.match(/strcpy\s*\(\s*([a-zA-Z0-9_]+)\s*,\s*([a-zA-Z0-9_]+)\s*\)/);
                if (m) {
                    return `${indent}strncpy(${m[1]}, ${m[2]}, sizeof(${m[1]}) - 1);\n${indent}${m[1]}[sizeof(${m[1]}) - 1] = '\\0';`;
                }
                return line;
            }
        },
        {
            pattern: /printf\s*\(\s*([a-zA-Z0-9_]+)\s*\)/i,
            category: "Format String Memory Vulnerability",
            cwe: "CWE-134",
            severity: vscode.DiagnosticSeverity.Error,
            fix: (line, indent) => {
                const m = line.match(/printf\s*\(\s*([a-zA-Z0-9_]+)\s*\)/);
                if (m) {
                    return `${indent}printf("%s\\n", ${m[1]});`;
                }
                return line;
            }
        }
    ]
};

// Aliases
RULES.typescript = RULES.javascript;
RULES.c = RULES.cpp;

let diagnosticCollection;
const quickFixStore = new Map();

function getLanguageKey(languageId) {
    if (languageId === 'python') return 'python';
    if (languageId.includes('javascript') || languageId.includes('typescript')) return 'javascript';
    if (languageId === 'cpp' || languageId === 'c') return 'cpp';
    return null;
}

function analyzeDocument(document) {
    const langKey = getLanguageKey(document.languageId);
    if (!langKey || !RULES[langKey]) return [];

    const diagnostics = [];
    const fixes = [];
    const rules = RULES[langKey];

    for (let i = 0; i < document.lineCount; i++) {
        const line = document.lineAt(i);
        const text = line.text;
        const indentMatch = text.match(/^\s*/);
        const indent = indentMatch ? indentMatch[0] : '';

        for (const rule of rules) {
            if (rule.pattern.test(text)) {
                const range = new vscode.Range(i, indent.length, i, text.length);
                const diag = new vscode.Diagnostic(
                    range,
                    `[AutoPatch AI] (${rule.cwe}) ${rule.category}: Potential security flaw or crash hazard.`,
                    rule.severity
                );
                diag.source = 'AutoPatch AI';
                diag.code = rule.cwe;

                const fixedCode = rule.fix(text, indent);
                diagnostics.push(diag);
                fixes.push({
                    range,
                    original: text,
                    fixed: fixedCode,
                    category: rule.category,
                    cwe: rule.cwe
                });
                break;
            }
        }
    }

    diagnosticCollection.set(document.uri, diagnostics);
    quickFixStore.set(document.uri.toString(), fixes);
    return diagnostics;
}

function activate(context) {
    diagnosticCollection = vscode.languages.createDiagnosticCollection('autopatch');
    context.subscriptions.push(diagnosticCollection);

    // Scan active editor on open
    if (vscode.window.activeTextEditor) {
        analyzeDocument(vscode.window.activeTextEditor.document);
    }

    // Scan on document changes / open
    context.subscriptions.push(
        vscode.workspace.onDidOpenTextDocument(doc => analyzeDocument(doc)),
        vscode.workspace.onDidChangeTextDocument(e => analyzeDocument(e.document)),
        vscode.workspace.onDidSaveTextDocument(doc => {
            const config = vscode.workspace.getConfiguration('autopatch');
            if (config.get('scanOnSave', true)) {
                analyzeDocument(doc);
            }
        })
    );

    // Register Code Action Provider (QuickFix Lightbulb)
    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider(
            ['python', 'javascript', 'typescript', 'cpp', 'c'],
            {
                provideCodeActions(document, range, context) {
                    const fixes = quickFixStore.get(document.uri.toString()) || [];
                    const actions = [];

                    for (const fix of fixes) {
                        if (fix.range.intersection(range)) {
                            const action = new vscode.CodeAction(
                                `🛡️ AutoPatch: Fix ${fix.category} (${fix.cwe})`,
                                vscode.CodeActionKind.QuickFix
                            );
                            action.isPreferred = true;
                            action.edit = new vscode.WorkspaceEdit();
                            // Replace whole line
                            const fullLineRange = document.lineAt(fix.range.start.line).range;
                            action.edit.replace(document.uri, fullLineRange, fix.fixed);
                            actions.push(action);
                        }
                    }
                    return actions;
                }
            },
            {
                providedCodeActionKinds: [vscode.CodeActionKind.QuickFix]
            }
        )
    );

    // Register Manual Scan Command
    context.subscriptions.push(
        vscode.commands.registerCommand('autopatch.scanFile', () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showWarningMessage('AutoPatch AI: No active file to scan.');
                return;
            }
            const diags = analyzeDocument(editor.document);
            if (diags.length === 0) {
                vscode.window.showInformationMessage('🛡️ AutoPatch AI: 0 flaws detected. Clean file!');
            } else {
                vscode.window.showWarningMessage(`🛡️ AutoPatch AI: ${diags.length} issue(s) detected! Check highlighted lines.`);
            }
        })
    );

    // Register Self-Heal Command
    context.subscriptions.push(
        vscode.commands.registerCommand('autopatch.healFile', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) return;

            const fixes = quickFixStore.get(editor.document.uri.toString()) || [];
            if (fixes.length === 0) {
                vscode.window.showInformationMessage('AutoPatch AI: File is clean, no patches needed.');
                return;
            }

            const edit = new vscode.WorkspaceEdit();
            // Apply fixes in reverse order
            const sorted = [...fixes].sort((a, b) => b.range.start.line - a.range.start.line);
            for (const fix of sorted) {
                const lineRange = editor.document.lineAt(fix.range.start.line).range;
                edit.replace(editor.document.uri, lineRange, fix.fixed);
            }

            await vscode.workspace.applyEdit(edit);
            await editor.document.save();
            vscode.window.showInformationMessage(`🛡️ AutoPatch AI: Surgically applied ${fixes.length} fix(es)!`);
        })
    );
}

function deactivate() {
    if (diagnosticCollection) {
        diagnosticCollection.clear();
        diagnosticCollection.dispose();
    }
}

module.exports = {
    activate,
    deactivate
};
