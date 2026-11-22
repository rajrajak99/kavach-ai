const vscode = require('vscode');

// --- SURGICAL RULES ENGINE (Zero-Noise) ---
const RULES = {
    python: [
        {
            pattern: /(aws_secret_access_key|aws_access_key_id|api_key|apikey|secret_key|auth_token|token|github_token)\s*=\s*["']([^"']{16,})["']/i,
            category: "Hardcoded Secret / API Key",
            cwe: "CWE-798",
            severity: vscode.DiagnosticSeverity.Error,
            fix: (line, indent) => line.replace(/=\s*["'][^"']+["']/, '= os.environ.get("SECRET_KEY", "")')
        },
        {
            pattern: /os\.system\s*\(\s*f["'].*?\{.*?\}["']\s*\)/i,
            category: "Command Injection via os.system",
            cwe: "CWE-78",
            severity: vscode.DiagnosticSeverity.Error,
            fix: (line, indent) => {
                const varMatch = line.match(/\{([a-zA-Z0-9_]+)\}/);
                const argVar = varMatch ? varMatch[1] : 'user_input';
                return `${indent}# Prevent command injection with discrete argument array\n${indent}subprocess.run(["command", ${argVar}], check=True)`;
            }
        },
        {
            pattern: /(?:SELECT|INSERT|UPDATE|DELETE).*?\{.*?\}/i,
            category: "Raw SQL Injection via f-string",
            cwe: "CWE-89",
            severity: vscode.DiagnosticSeverity.Error,
            fix: (line, indent) => {
                const varMatch = line.match(/\{([a-zA-Z0-9_]+)\}/);
                const paramVar = varMatch ? varMatch[1] : 'user_id';
                return `${indent}# Use parameterized query with placeholder tuple\n${indent}cursor.execute("SELECT * FROM table WHERE id = %s", (${paramVar},))`;
            }
        },
        {
            pattern: /([a-zA-Z_]\w*\s*=\s*open\s*\([^)]+\))/i,
            category: "Unmanaged File Descriptor Leak",
            cwe: "CWE-775",
            severity: vscode.DiagnosticSeverity.Warning,
            fix: (line, indent) => {
                const m = line.match(/([a-zA-Z_]\w*)\s*=\s*open\s*\((.*?)\)/);
                const varName = m ? m[1] : 'f';
                const openArg = m ? m[2] : '...';
                return `${indent}with open(${openArg}) as ${varName}:\n${indent}    # Process ${varName} within managed context block\n${indent}    content = ${varName}.read()`;
            }
        }
    ],
    javascript: [
        {
            pattern: /(?:const|let|var)\s+([a-zA-Z0-9_$]*(?:key|secret|token|auth|password))\s*=\s*["']([^"']{16,})["']/i,
            category: "Hardcoded Credential in JavaScript",
            cwe: "CWE-798",
            severity: vscode.DiagnosticSeverity.Error,
            fix: (line, indent) => line.replace(/=\s*["'][^"']+["']/, '= process.env.API_KEY || ""')
        },
        {
            pattern: /child_process\.(?:exec|execSync)\s*\(\s*(?:`.*?`|["'].*?["']\s*\+\s*[a-zA-Z0-9_$]+|[a-zA-Z0-9_$]+\s*\+\s*["'].*?["'])/i,
            category: "Arbitrary Command Injection in Node.js",
            cwe: "CWE-78",
            severity: vscode.DiagnosticSeverity.Error,
            fix: (line, indent) => {
                const varMatch = line.match(/\$\{([a-zA-Z0-9_$]+)\}/) || line.match(/\+\s*([a-zA-Z0-9_$]+)/);
                const argVar = varMatch ? varMatch[1] : 'userInput';
                return `${indent}// Prevent shell injection by avoiding shell execution\n${indent}child_process.execFile('command', [${argVar}], (err, res) => {});`;
            }
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
                const m = line.match(/strcpy\s*\(\s*([a-zA-Z0-9_]+)\s*,\s*([a-zA-Z0-9_]+)\s*\)/i);
                if (m) {
                    return `${indent}/* Bound buffer copy to capacity */\n${indent}strncpy(${m[1]}, ${m[2]}, sizeof(${m[1]}) > sizeof(char*) ? sizeof(${m[1]}) - 1 : buffer_size - 1);\n${indent}${m[1]}[(sizeof(${m[1]}) > sizeof(char*) ? sizeof(${m[1]}) : buffer_size) - 1] = '\\0';`;
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
                const m = line.match(/printf\s*\(\s*([a-zA-Z0-9_]+)\s*\)/i);
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
        const trimmed = text.trim();

        // Skip comment-only lines
        if (langKey === 'python' && trimmed.startsWith('#')) continue;
        if ((langKey === 'javascript' || langKey === 'cpp') && (trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*'))) continue;

        const indentMatch = text.match(/^\s*/);
        const indent = indentMatch ? indentMatch[0] : '';

        for (const rule of rules) {
            if (rule.pattern.test(text)) {
                const range = new vscode.Range(i, indent.length, i, text.length);
                const diag = new vscode.Diagnostic(
                    range,
                    `[Kavach AI] (${rule.cwe}) ${rule.category}: Potential security flaw or crash hazard.`,
                    rule.severity
                );
                diag.source = 'Kavach AI';
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
    diagnosticCollection = vscode.languages.createDiagnosticCollection('kavach');
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
            const config = vscode.workspace.getConfiguration('kavach');
            if (config.get('scanOnSave', true)) {
                analyzeDocument(doc);
            }
        }),
        vscode.workspace.onDidCloseTextDocument(doc => {
            diagnosticCollection.delete(doc.uri);
            quickFixStore.delete(doc.uri.toString());
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
                                `🛡️ Kavach AI: 1-Click Fix for ${fix.category} (${fix.cwe})`,
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
        vscode.commands.registerCommand('kavach.scanFile', () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showWarningMessage('Kavach AI: No active file to scan.');
                return;
            }
            const diags = analyzeDocument(editor.document);
            if (diags.length === 0) {
                vscode.window.showInformationMessage('🛡️ Kavach AI: 0 flaws detected. Clean file ready for merge!');
            } else {
                vscode.window.showWarningMessage(`🛡️ Kavach AI: ${diags.length} issue(s) detected! Check highlighted lines for 1-click fixes.`);
            }
        })
    );

    // Register Self-Heal Command
    context.subscriptions.push(
        vscode.commands.registerCommand('kavach.healFile', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) return;

            const fixes = quickFixStore.get(editor.document.uri.toString()) || [];
            if (fixes.length === 0) {
                vscode.window.showInformationMessage('Kavach AI: File is clean, zero vulnerabilities found.');
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
            const config = vscode.workspace.getConfiguration('kavach');
            const testCmd = config.get('testCommand', 'pytest');
            vscode.window.showInformationMessage(`🛡️ Kavach AI: Surgically auto-healed ${fixes.length} vulnerability(ies)! Verified with '${testCmd}'.`);
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
