

---

# Living Off the Land

**Living Off the Land**

This section covers AD enumeration using only native Windows tools—no uploads or external tools required.

**Scenario:**
The client requests testing from a managed host without internet access where all tool loading attempts have failed. The objective is to demonstrate enumeration capabilities using only built-in Windows/AD tools ("living off the land").

**Advantages:**
- **Stealth:** Generates fewer log entries and alerts compared to external tools
- **Evasion:** Avoids triggering detection in environments with:
  - Network monitoring and logging (IDS/IPS, firewalls, passive sensors)
  - Host-based defenses (Windows Defender, enterprise EDR)
  - Baseline anomaly detection tools

**Risk Consideration:**
Pulling external tools into the environment exponentially increases detection likelihood. Native tool usage reduces this exposure significantly.








































