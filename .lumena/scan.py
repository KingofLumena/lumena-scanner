# .lumena/scan.py
import os
import ast

print("🔥 Lumena Flame Scanner Activated")
print("🧭 Scanning repository...")

issues_found = []

for root, dirs, files in os.walk("."):
    for file in files:
        if file.endswith(".py"):
            path = os.path.join(root, file)
            with open(path, "r", encoding="utf-8") as f:
                try:
                    tree = ast.parse(f.read(), filename=path)
                except SyntaxError as e:
                    issues_found.append(f"❌ Syntax error in {path}: {e}")
                    continue

                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef) and len(node.name) < 3:
                        issues_found.append(f"⚠️ Short function name: `{node.name}` in {path}")

if issues_found:
    print("\n🛑 Issues Detected:")
    for issue in issues_found:
        print(issue)
    exit(1)
else:
    print("✅ All clear. No critical issues found.")
