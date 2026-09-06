#!/bin/bash
set -euo pipefail

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x02_assets}"
RISK_REGISTER="$ASSETS_DIR/risk_register.json"
RULE_QUALITY="rule_quality.json"
RULES_DIR="rules/sigma"
TUNED_DIR="rules/sigma/tuned"
OUTPUT_JSON="rule_prioritization.json"

python3 - "$RISK_REGISTER" "$RULE_QUALITY" "$RULES_DIR" "$TUNED_DIR" "$OUTPUT_JSON" << 'PY'
import sys
import os
import json
import yaml
import glob

risk_register_path = sys.argv[1]
rule_quality_path = sys.argv[2]
rules_dir = sys.argv[3]
tuned_dir = sys.argv[4]
output_json_path = sys.argv[5]

# 1. Load Risk Register
risk_scenarios = []
if os.path.exists(risk_register_path):
    try:
        with open(risk_register_path, 'r', encoding='utf-8') as f:
            content = json.load(f)
            if isinstance(content, list):
                risk_scenarios = content
            elif isinstance(content, dict):
                risk_scenarios = content.get('scenarios', content.get('risk_register', []))
    except Exception as e:
        print(f"Warning: Could not parse risk register: {e}", file=sys.stderr)

# 2. Load Rule Quality Data
quality_data = {}
if os.path.exists(rule_quality_path):
    try:
        with open(rule_quality_path, 'r', encoding='utf-8') as f:
            for item in json.load(f):
                quality_data[item.get("rule_title")] = item
    except Exception as e:
        print(f"Warning: Could not parse rule quality JSON: {e}", file=sys.stderr)

# 3. Find all rules and extract their ATT&CK tags and metadata
rule_paths = []
for d in [rules_dir, tuned_dir]:
    if os.path.exists(d):
        for root, _, files in os.walk(d):
            for file in files:
                if file.endswith(('.yml', '.yaml')):
                    rule_paths.append(os.path.join(root, file))

evaluated_rules = []
orphans = []

for rpath in sorted(rule_paths):
    try:
        with open(rpath, 'r', encoding='utf-8') as f:
            rdata = yaml.safe_load(f)
    except Exception:
        continue

    rule_title = rdata.get("title", os.path.basename(rpath))
    rule_id = rdata.get("id", "unknown")
    level = rdata.get("level", "medium")
    
    # Extract tags starting with attack.t or similar
    tags = rdata.get("tags", [])
    rule_techniques = set()
    for tag in tags:
        tag_lower = str(tag).lower()
        if "attack.t" in tag_lower:
            # e.g., attack.t1087 -> t1087 or 1087
            tech = tag_lower.split("attack.")[-1].upper()
            rule_techniques.add(tech)

    # Get F1 from quality data if available
    q_info = quality_data.get(rule_title, {})
    f1 = q_info.get("f1", 0.0)

    # Calculate risk score based on matching risk scenarios
    risk_score = 0.0
    covering_scenarios = []

    for scenario in risk_scenarios:
        # Check scenario techniques
        s_techniques = scenario.get("techniques", scenario.get("attack_techniques", []))
        s_tech_set = {str(t).upper() for t in s_techniques}
        
        # Check intersection
        if rule_techniques & s_tech_set:
            likelihood = float(scenario.get("likelihood", scenario.get("likelihood_score", 1)))
            impact = float(scenario.get("impact", scenario.get("impact_score", 1)))
            risk_score += likelihood * impact
            s_name = scenario.get("name", scenario.get("id", "unknown_scenario"))
            covering_scenarios.append(s_name)

    # Compute priority score
    if risk_score == 0:
        # Check if any scenario matches by broader tag or if it's an orphan
        orphans.append(os.path.basename(rpath))
        priority_score = 0.0
    else:
        if f1 == 0:
            priority_score = risk_score * 0.1
        else:
            priority_score = risk_score * f1

    priority_score = round(priority_score, 2)
    risk_score = round(risk_score, 2)

    evaluated_rules.append({
        "rule_id": rule_id,
        "rule_title": rule_title,
        "filename": os.path.basename(rpath),
        "risk_score": risk_score,
        "f1": f1,
        "priority_score": priority_score,
        "covering_scenarios": covering_scenarios,
        "level": level
    })

# Sort by priority_score descending
evaluated_rules_sorted = sorted(evaluated_rules, key=lambda x: (x["priority_score"], x["risk_score"]), reverse=True)

# Write output JSON
with open(output_json_path, 'w', encoding='utf-8') as f:
    json.dump(evaluated_rules_sorted, f, indent=2)

# Print Top 10
print("top 10 rules by priority_score")
for idx, r in enumerate(evaluated_rules_sorted[:10], 1):
    short_name = r["filename"].replace('.yml', '').replace('.yaml', '')
    print(f"{idx:2d}  {r['priority_score']:4.1f}  {short_name}")

print(f"orphan rules (no risk scenario covers) : {len(orphans)}")
print(f"{output_json_path} written")
PY
