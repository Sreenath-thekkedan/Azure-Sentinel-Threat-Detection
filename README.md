# 🔐 Threat Detection & Monitoring with Azure Sentinel  
*A hands-on project simulating brute-force attacks and malware activity on Windows & Linux endpoints.*

---

## 📌 Project Overview  
This project demonstrates how Azure Sentinel can be used to detect, analyze, and respond to security threats such as:

- Brute force attacks  
- Malware detections  
- Suspicious IP activity  
- Cross-platform log ingestion  
- Automated incident creation  

The setup included **both Windows and Linux endpoints**, Sentinel analytics rules, KQL queries, simulated attacks, and SOC-style reporting.

---

## 🧱 Architecture  

Reference  **Page 1** of the project report 

---

## 🎯 Key Objectives

- Configure Azure Sentinel to collect data from Windows & Linux
- Create analytics rules to detect brute force and malware threats
- Simulate attacks to validate alerting
- Automate incident generation for SOC workflows

---

## ⚙️ Environment Setup

### **1. Azure Sentinel Workspace**
- New Log Analytics workspace configured  
- Sentinel enabled for monitoring

### **2. Data Connectors**
- **Windows Endpoint:** Azure Monitoring Agent (AMA) installed  
- **Linux Endpoint:** Syslog via AMA installed using Data Collection Rules  

---

## 🔍 Analytics Rules

### **Brute Force Detection**

#### **Windows:**
Detects 10+ failed logons within 10 minutes.

KQL:
```kql
SecurityEvent
| where EventID == 4625
| summarize FailedLogons = count() by Computer, IPAddress, bin(TimeGenerated, 10m)
| where FailedLogons > 10
