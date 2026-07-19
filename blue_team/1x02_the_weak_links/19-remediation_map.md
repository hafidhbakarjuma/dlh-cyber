# 19. The Remediation Map

## Finding 001
* **Response Type**: Patch
* **Patch Source**: Fortinet Support Portal (firmware update)
* **Prerequisites**: System backup, test on staging appliance, maintenance window coordination
* **Rollback Plan**: Revert to previous firmware image via boot menu
* **Operational Risk**: Service disruption during reboot, configuration incompatibility
* **Timeline**: Immediate
* **Owner**: IT
* **Cost Estimate**: $1-10K

---
## Finding 002
* **Response Type**: Patch
* **Patch Source**: Microsoft Update Catalog (KB patch)
* **Prerequisites**: Domain Controller state backup, AD database integrity check
* **Rollback Plan**: Uninstall patch, restore DC from backup
* **Operational Risk**: AD replication failure, authentication service downtime
* **Timeline**: Immediate
* **Owner**: IT
* **Cost Estimate**: $0-1K

---
## Finding 003
* **Response Type**: Patch
* **Patch Source**: Apache Tomcat official site
* **Prerequisites**: Database backup, staging environment test, clinical notification
* **Rollback Plan**: Restore application server snapshot
* **Operational Risk**: Application incompatibility with EHR database, potential service outage
* **Timeline**: Immediate
* **Owner**: IT/Vendor
* **Cost Estimate**: $10-50K

---
## Finding 004
* **Response Type**: Compensating Control
* **Control Description**: Network isolation (VLAN containment) via switch configuration
* **Residual Risk**: None, except for complete loss of device network connectivity
* **Timeline**: Immediate
* **Owner**: Security
* **Cost Estimate**: $0-1K

---
## Finding 006
* **Response Type**: Configuration Change
* **Change Description**: Change default vendor credentials to complex, unique passwords for all gateways
* **Impact Assessment**: Requires manual reconfiguration of all connected medical devices
* **Timeline**: 7 days
* **Owner**: IT
* **Cost Estimate**: $1-10K

---
## Finding 008
* **Response Type**: Exception
* **Justification**: FDA-validated clinical device; firmware upgrade requires vendor-certified process
* **Review Date**: 30 days
* **Monitoring**: Strict network segmentation and outbound traffic filtering
* **Timeline**: 30 days
* **Owner**: Clinical/Vendor
* **Cost Estimate**: $10-50K

---
## Finding 009
* **Response Type**: Exception
* **Justification**: FDA-validated clinical device; firmware upgrade requires vendor-certified process
* **Review Date**: 30 days
* **Monitoring**: Strict network segmentation and outbound traffic filtering
* **Timeline**: 30 days
* **Owner**: Clinical/Vendor
* **Cost Estimate**: $10-50K

---
## Finding 031
* **Response Type**: Patch
* **Patch Source**: Apache Tomcat official site
* **Prerequisites**: Database backup, staging environment test, clinical notification
* **Rollback Plan**: Restore application server snapshot
* **Operational Risk**: Application incompatibility with EHR database, potential service outage
* **Timeline**: Immediate
* **Owner**: IT/Vendor
* **Cost Estimate**: $10-50K

---
