# Structured Trade-off Analysis: CLI vs. Wazuh Export

| Scenario ID | CLI Time (s) | Export Time (s) | Delta (s) | Faster Interface | Primary Advantage / Operational Cause |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **anchor** | 45 | 22 | 23 | wazuh_export | native_field_surface |
| **scenario_a** | 52 | 33 | 19 | wazuh_export | timeline_visualization |
| **scenario_b** | 45 | 25 | 20 | wazuh_export | reproducibility |
| **scenario_c** | 38 | 21 | 17 | wazuh_export | pipeline_expressiveness |

## Summary
* **Export Advantages**: 4 scenarios (Pre-indexed telemetry and exported trace artifacts eliminate live query latency).
* **CLI Advantages**: 0 scenarios (Command-line filtering requires explicit dataset loading and query composition).
