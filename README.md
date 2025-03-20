![image](https://github.com/user-attachments/assets/9b829f74-80bd-4ff5-ad90-0fa744edbb1e)

## 🔒 Threat Event: Unauthorized Gambling Website Access & History Deletion

### **John Doe Accessing Gambling Sites Despite Prior Warnings & Deleting Browser History**

#### **Example Scenario**
John Doe (aka **labuserich**) has been **previously warned** about accessing gambling websites such as **FanDuel** and **DraftKings** during work hours. His manager suspects that he is still **visiting these sites** and **actively deleting his browser history** to cover his tracks. The security team has been tasked with **conducting an investigation** to confirm whether John is violating company policy.

---

### **🔍 Reason for the Hunt**
- **John Doe has a history of visiting gambling websites** during work hours.
- **He is suspected of deleting his browsing history** to avoid detection.
- The security team must **verify and document** whether policy violations continue.

---

## **⚠️ Steps the "Bad Actor" Took to Create Logs and IoCs**

### **1️⃣ Access Gambling Websites on Work Computer**
- John visits gambling websites like **fanduel.com** and **draftkings.com** before the **Sunday NFL games**.
- He **places sports bets and enters parlays** while at work.

### **2️⃣ Deletes Browser History to Cover Tracks**
- After placing his bets, John **manually deletes his browsing history** from **Firefox**.
- Alternatively, he uses **private/incognito mode** to prevent history from being stored.

### **3️⃣ Attempts to Bypass Security Controls**
- John may use **VPN services or proxy websites** to hide his traffic.
- He may clear **DNS cache** using the following command in CMD to remove traces:
  ```cmd
  ipconfig /flushdns
  ```

### **4️⃣ Continued Policy Violations**
- Despite **prior warnings**, John continues this behavior, making it necessary for security to **investigate further**.

---

## **🔧 High-Level Firefox Browser History Detection Discovery Plan**
- **Check `DeviceNetworkEvents`** for any signs of **outgoing connections** to FanDuel or DraftKings Sportsbook.
- **Check `DeviceProcessEvents`** for any signs of **incognito mode usage** or command-line **clearing of DNS cache**.
- **Check `DeviceFileEvents`** for any **browser history deletion** and other suspicious file modifications.

---

## **🔍 Steps Taken During Investigation**

### **1️⃣ Initial Querying**
- Started with baseline queries for **DeviceNetworkEvents, DeviceProcessEvents, and DeviceFileEvents**.
- This provided a foundation to identify key activity related to **unauthorized gambling site access and deletion of evidence**.

### **2️⃣ Identified Gambling Website Access**
- Within the first **five minutes**, I discovered that **John had visited FanDuel and DraftKings** using the following query:
  ```kql
  DeviceNetworkEvents
  | where RemoteUrl has_any ("fanduel.com", "draftkings.com")
  ```
- Multiple **successful connections** confirmed access to restricted sites.

### **3️⃣ Investigated Private Browsing Mode Usage**
- Used `DeviceProcessEvents` to check for **incognito mode usage in Firefox**.
- While **no explicit evidence** of `-private` mode was found, **Firefox was launched at 4:38 PM**, aligning with the gambling site access.

> **⚠️ Note:** Even though private browsing mode was used, the logs still recorded a process creation event at the time of gambling site access.

### **4️⃣ Detected DNS Cache Flush – Attempt to Hide Evidence**
- **Queried `DeviceProcessEvents`** for `ipconfig /flushdns` executions.
- **At 5:22 PM**, `ipconfig.exe /flushdns` was executed by John.
- **This suggests an intentional attempt** to remove traces of site visits from the DNS cache.

### **5️⃣ Investigated Browser History Deletion**
- **Queried `DeviceFileEvents`** for `places.sqlite` deletion (Firefox history database).
- **Initial query found no results**.
- Upon further investigation, **a `FileDeleted` event was discovered at 4:11 PM** under:
  ```plaintext
  C:\Users\labuserich\AppData\Local\Temp\7zSC1834886\core\firefox.exe
  ```
- This suggests a **possible attempt to delete temporary browsing data**, but does not directly confirm browsing history deletion.

---

## **🚨 Final Assessment**
- **✅ Confirmed Unauthorized Gambling Website Access** – John actively accessed **FanDuel & DraftKings during work hours**.
- **✅ Confirmed Attempt to Evade Detection** – A **DNS cache flush** was executed, likely to remove traces of site visits.
- **❓ Possible History Deletion** – No direct deletion of `places.sqlite`, but **Firefox-related file deletions** raise concerns.

---

## **📢 Conclusion**
The user **"labuserich" (John Doe)** has demonstrated a **clear pattern of policy violations**:
1. **Visiting restricted gambling websites** during work hours.
2. **Potentially using private browsing mode** to avoid detection.
3. **Clearing DNS logs** to remove evidence.
4. **Deleting Firefox-related files**, potentially linked to browser history cleanup.

🔍 **While no direct deletion of browsing history was found, the combined actions strongly indicate an attempt to avoid detection.**

---

## **🔍 Recommended Next Steps**
1. **Monitor DNS & Web Traffic** – Implement **alerts** for visits to gambling sites.
2. **Check for Additional File Modifications** – Investigate further file deletions in **Firefox profile directories**.
3. **Enforce Security Controls** – Consider **blocking gambling websites at the network level**.
4. **Escalate to HR/Management** – Given **prior warnings**, further disciplinary action may be required.

Would you like assistance in setting up **proactive monitoring or additional forensic analysis**? 🚀

---

## Chronological Event Timeline 


## 📅 Detailed Timeline of Unauthorized Gambling Website Access & History Deletion


| **Timestamp (UTC)**       | **Event Type**         | **Action**                              | **Process / File**                                         | **File Path / URL** |
|--------------------------|-----------------------|-----------------------------------------|------------------------------------------------------------|----------------------|
| **4:38 PM**             | **Process Execution**  | **Firefox Launched (Possible Private Mode)** | `firefox.exe`                                          | `C:\Program Files\Mozilla Firefox\firefox.exe` |
| **4:39 PM**             | **Network Activity**   | **Accessed Gambling Website**          | `firefox.exe` (User Browsing)                             | `assets.sportsbook.fanduel.com` |
| **4:39 PM**             | **Network Activity**   | **Accessed Gambling Website**          | `firefox.exe` (User Browsing)                             | `papi.sportsbook.fanduel.com` |
| **4:39 PM**             | **Network Activity**   | **Accessed Gambling Website**          | `firefox.exe` (User Browsing)                             | `gaming-us-va.draftkings.com` |
| **4:11 PM**             | **File Deletion**      | **Firefox Temporary Files Deleted**    | `firefox.exe`                                            | `C:\Users\labuserich\AppData\Local\Temp\7zSC1834886\core\firefox.exe` |
| **5:22 PM**             | **Command Execution**  | **Flushed DNS Cache**                   | `ipconfig.exe`                                           | `C:\Windows\System32\ipconfig.exe /flushdns` |


---


## 🛡️ Detailed Summary


### **1️⃣ Unauthorized Access to Gambling Websites**
- At **4:39 PM**, user **"labuserich"** accessed multiple gambling websites, including **FanDuel** and **DraftKings**.
- **Website connections included:**
  - `assets.sportsbook.fanduel.com`
  - `papi.sportsbook.fanduel.com`
  - `gaming-us-va.draftkings.com`


### **2️⃣ Possible Private Browsing Mode Usage**
- At **4:38 PM**, `firefox.exe` was launched.
- **No explicit log evidence of private browsing mode (`-private` flag)**, but process creation aligns **exactly** with gambling website visits.


### **3️⃣ DNS Cache Flush – Attempt to Cover Tracks**
- At **5:22 PM**, `ipconfig.exe /flushdns` was executed, indicating **an attempt to erase traces of visited websites**.
- **This action removes cached DNS resolutions, making it harder to track past site visits.**


### **4️⃣ Suspicious File Deletion – Possible Browser History Wipe**
- At **4:11 PM**, a **FileDeleted event was recorded for Firefox-related files**.
- The deleted file path suggests **temporary browser data cleanup**, but **direct deletion of browser history (`places.sqlite`) was not found**.
- **This strongly suggests an attempt to cover tracks, it is to be noted that DeviceNetworkEvents logged him visiting the sites until approx 4:30 pm.**


---


## 🚨 **Final Assessment**
- **✅ Confirmed Unauthorized Gambling Website Access** – The user **actively accessed FanDuel & DraftKings during work hours**.
- **✅ Confirmed Attempt to Evade Detection** – A **DNS cache flush** was executed, likely to remove traces of website visits.
- **❓ Possible History Deletion** – While **direct evidence of browser history deletion was not found**, the deletion of Firefox-related files suggests an attempt to erase browsing activity.


---


## 📢 **Conclusion**
The user **"labuserich" (John Doe)** has demonstrated a **clear pattern of policy violations**:
1. **Visiting restricted gambling websites** during work hours.
2. **Potentially using private browsing mode** to avoid detection.
3. **Clearing DNS logs** to remove evidence.
4. **Deleting Firefox-related files**, potentially linked to browser history cleanup.


🔍 **While no direct deletion of browsing history was found, the combined actions strongly indicate an attempt to avoid detection.**


---


## 🔍 **Recommended Next Steps**
1. **Monitor DNS & Web Traffic** – Implement **alerts** for visits to gambling sites.
2. **Check for Additional File Modifications** – Investigate further file deletions in **Firefox profile directories**.
3. **Enforce Security Controls** – Consider **blocking gambling websites at the network level**.
4. **Escalate to HR/Management** – Given **prior warnings**, further disciplinary action may be required.

  
---

## Response Taken

TOR usage was confirmed on the endpoint rich-mde-test by the user labuserich. The device was isolated, and the user's direct manager was notified.

---
