### 🕵️Network Analysis with Wireshark and OSINT tools (Hawkeye from CyberDefenders.org)

<img width="1468" height="512" alt="R (2)" src="https://github.com/user-attachments/assets/1d628b24-d64b-4906-ae6d-ee131a0fb791" />

## 🎯 Scenario

An accountant at your organization received an email containing an "invoice" download link. Suspicious network activity followed shortly after. As a SOC Analyst, your mission is to investigate the network capture file and determine if data exfiltration or malware activity occurred.

---

## 🧰 Tools Used

| Tool         | Purpose                                 |
|--------------|-----------------------------------------|
| Wireshark    | Packet capture inspection               |
| CyberChef    | Base64 decoding of SMTP credentials     |
| PowerShell   | Hash calculation for the executable     |
| VirusTotal   | File/domain reputation checks           |
| DomainTools  | WHOIS domain analysis                   |
| FileScan.IO  | Behavioral malware analysis             |

---

## 🔢 Step-by-Step Investigation

### 1. Capture Download and Overview
- File Name: `stealer.pcap`
- Capture Length: `01:03:41`
- First Packet: `2019-04-10 16:37:07`
- Last Packet: `2019-04-10 17:40:48`
- File Size: `~2.5 MB`

<img width="631" height="138" alt="1  Download the pcap file" src="https://github.com/user-attachments/assets/43cb2d30-56bc-4a2a-b33b-135739dc190e" />

<img width="1264" height="367" alt="2  Check the duration of the capture in Statistics" src="https://github.com/user-attachments/assets/ecd0bf9d-4e00-4aea-91cc-faa17f36d7d4" />

---

### 2. Protocol Analysis
- TCP dominates with **93.3%** of total traffic.
- Other notable protocols: HTTP, SMTP, DNS, NBNS.
- This mix strongly suggests download and exfiltration activity.

<img width="1317" height="584" alt="3  Checking the Protocol Hierarchy to see the protocols that we are messing with" src="https://github.com/user-attachments/assets/f1b63d55-e0cf-4c66-81fa-9190134cc893" />

---

### 3. Conversations – Top Talkers
- `10.4.10.132` communicated with:
  - `217.182.138.150` (HTTP)
  - `23.229.162.69` (SMTP)
  
<img width="757" height="301" alt="4  Checking the Conversations to see the top talkers , and we can see three main suspicious IP addresses" src="https://github.com/user-attachments/assets/3ba23fda-8a9d-4de6-bb9d-fe260d3f5656" />

---

### 4. SMTP Activity Analysis
- Many SMTP sessions between `10.4.10.132` and `23.229.162.69`
- Repeated use of **port 587**

<img width="1275" height="546" alt="5  Checking too se in the TCP tab the ports and we can notice than this IP address is probably the mail sender  by looking the port 587 listed" src="https://github.com/user-attachments/assets/2a15bc55-dc7e-4867-94f8-ba076b346845" />

---

### 5. HTTP Malware Download Identified
- Filtered the top IP ip.addr == 217.182.138.150 and noticed Packet 210 shows a suspicious HTTP request `GET /proforma/tkraw_Protected99.exe HTTP/1.1`

<img width="1365" height="496" alt="6  Using the filter for the top Ip talker, I notice that number 210, there is a http packet" src="https://github.com/user-attachments/assets/94212e6a-8182-4ae6-b5b0-2f22cbc79dce" />

- Went to the HTTP stream of the packet and took a better look, and we see binary being downloaded
- Host: `proforma-invoices.com`
- Content-Type: `application/x-msdownload`
- Confirmed Windows PE with `MZ` header

<img width="898" height="618" alt="7  Went to the HTTP stream of the packet and took a better look, and we see binary being downloaded" src="https://github.com/user-attachments/assets/65839fa9-6f0b-45a8-8cb4-25b848e7d726" />

---

### 6. DNS Resolution
- By checking the packet below 207, we can see that this could be the suspicious download link that was hinted
- `10.4.10.132` performs DNS query for:
- proforma-invoices.com
- Followed immediately by HTTP GET

<img width="1183" height="151" alt="8  By checking the packet below 207, we can that this could be the suspicious download link that was hinted" src="https://github.com/user-attachments/assets/8bdc72a4-1570-44b6-9a65-a5bdf68355e9" />

---
### 7. Filtered for SMTP 
- Filtering for `smtp` in Wireshark reveals that the IP `23.229.162.69` is the email sender. The packet arrival time confirms that the SMTP traffic occurred shortly after the malicious file was downloaded, indicating potential credential exfiltration.`

<img width="1236" height="467" alt="9  By putting smtp in the filter we noticed that the IP address that I mentioned before who was the email sender, and looking at the packet arrival time we noticed the that this smtp traffic happens aft" src="https://github.com/user-attachments/assets/b018fcbe-7a77-4a5d-90ce-10b0231e1918" />


---

### 8. SMTP Credential Theft
- Opening the TCP stream for packet 3175 reveals the SMTP banner details, including the mail server hostname (`p3plcpn10413.prod.phx3.secureserver.net`), its software (`Exim 4.91`), and the client machine name (`Beijing-5cd1-PC`).

<img width="902" height="707" alt="10  Opening the TCP Stream from 3175 packet we can see the host name of the mail server and the software version, and the client machine" src="https://github.com/user-attachments/assets/686f547b-fcb8-4497-acf6-9c9b9d17e158" />

- We can also see an authentication attempt

<img width="890" height="594" alt="11  We can also see an authentication attempt" src="https://github.com/user-attachments/assets/9c67e88d-c819-4983-9250-2054cdb2db84" />

---

### 9. Stolen Victim Data
- The login string was decoded in CyberChef using Base64 (identified by the `==` padding). The result revealed the attacker's email address used for SMTP authentication.

<img width="1092" height="361" alt="12  Went to CyberChef to decode the login, using Base64 because of the == at the end, and we got the result" src="https://github.com/user-attachments/assets/a29db22d-ac4a-4a0f-b2fc-b261648e2e12" />

- The Password was also decoded using Base64

<img width="1094" height="355" alt="13  I also did with the password, so we basically discovered the attacker's account" src="https://github.com/user-attachments/assets/d09aabda-791d-43ac-aeb7-f749694e0adb" />

- Now we can see the Content being decoded by Base64 showing the victim credentials, with **weak credentials** using the same password for all of his accounts including the his bank account

<img width="1094" height="331" alt="14  I've also did with the content, and we noticed that roman mcguire was the victim and also the really weak password he used for all different accounts" src="https://github.com/user-attachments/assets/10626cce-a032-42d0-80f3-b7d4818a2ab9" />
<img width="684" height="204" alt="15  even for bank of america" src="https://github.com/user-attachments/assets/ee4b1724-c8c6-4112-9467-f57bfcd8b366" />

- At last I checked the last packed from the filter input **SMTP** to check the content to see if there were any other account compromised. But it was the same victim.

<img width="1365" height="468" alt="16  So I wanted to check the last packet to make sure that was the account compromised, and it was the only one" src="https://github.com/user-attachments/assets/314b5410-9569-47e7-a88d-9408b9749248" />

---
### 10. Exported the File
- Exported the file as HTTP and we can see the **proforma-invoices.com** hostname and the malicious file **tkraw_Protected99.exe**
- I also noticed that the HTTP object list also shows a request to `bot.whatismyipaddress.com`, indicating the malware may use it to beacon out and identify the host's public IP address.

<img width="754" height="542" alt="18  Save the file that contained proforma as the hostname that contained a suspicious file, we also see the bot whatis  maybe it makes a scheduled query for myip" src="https://github.com/user-attachments/assets/7a90e4ef-db4b-43be-8ef8-362dc42f4cc8" />

- Saved the File with **.malware** so it wont be as **.exe** that could lead to it being run by mistake

<img width="672" height="110" alt="19  Add the malware at the end and saved it" src="https://github.com/user-attachments/assets/30e10c4e-681b-441f-81b9-acceee8d0d4a" />

- At last I opened Powershell and ran *GetFile-Hash** to get the hash of the file **tkraw_Protected99.exe** and we got a **SHA256** hash

<img width="1107" height="413" alt="20  Opened Terminal and used this command to find the sha256 hash for the file" src="https://github.com/user-attachments/assets/775edab6-4ad7-4ee9-8866-bb0624cc2567" />

---

### 11. 🌐OSINT Research
- Used VirusTotal to perform an OSINT check on the file’s SHA256 hash. The result confirmed the file is malicious

<img width="1365" height="630" alt="21  For some OSINT I opened VirusTotal to enter the hash and we confirmed that it is a malware" src="https://github.com/user-attachments/assets/594bebb0-e12b-4b98-b0b8-60786338284e" />

- In the VirusTotal Community tab, users confirmed the file as malicious, providing additional tags and context about its behavior.

<img width="1365" height="629" alt="22  Checking the community part showing people saying it is actually a malware" src="https://github.com/user-attachments/assets/5adac79b-115c-4a79-9bbe-39e8a72adbe8" />

- In VirusTotal’s Relations tab, we confirmed that the malware contacted `bot.whatismyipaddress.com`, suggesting it may be used for beaconing or external IP discovery.

<img width="1168" height="581" alt="23  And we confirmed in the Relations tab in the contacted domains the whatismyip host" src="https://github.com/user-attachments/assets/30f5e2b9-bb70-4182-9e60-9db272108fa2" />

- Also performed an OSINT lookup on **proforma-invoices.com** using VirusTotal. The domain was flagged as malicious by multiple vendors, confirming its role in delivering the malware.

<img width="1365" height="655" alt="24  Also did a OSINT for the proforma-invoices com and we can confirm it is malicious" src="https://github.com/user-attachments/assets/4d277fc9-27ff-4e14-a410-e4439786ab3b" />

- At last I checked `proforma-invoices.com` on DomainTools. The domain is currently unregistered and listed for sale, indicating it was likely used temporarily for malicious activity and then discarded.

<img width="1318" height="601" alt="25  Also checked in domain tools, and it is for sale" src="https://github.com/user-attachments/assets/6ad2cfe2-0d81-4667-ac57-61f9d2452121" />

### ✅ Conclusion
This investigation demonstrates a full-chain compromise starting with a phishing lure and ending with successful data exfiltration. By leveraging Wireshark, CyberChef, VirusTotal, and WHOIS tools, we were able to uncover the following:

1. 🎣 **Phishing Delivery**  
   The attacker sent a phishing email to an internal user containing a fake invoice link hosted on `proforma-invoices.com`.

2. 💾 **Malware Execution**  
   The victim downloaded and likely executed a suspicious binary (`tkraw_Protected99.exe`), confirmed to be a malicious Windows PE file.

3. 🔐 **Credential Harvesting**  
   Base64-encoded credentials exfiltrated via SMTP indicate that the malware included keylogging or browser scraping functionality. The victim reused weak passwords across multiple services—including banking.

4. 📤 **Exfiltration via SMTP**  
   Stolen data was transmitted to an attacker-controlled email server using port 587 (SMTP with authentication).

5. 🛰️ **Command & Control (C2) Beaconing**  
   The malware contacted `bot.whatismyipaddress.com`, likely to identify its public IP—behavior often seen in C2 beaconing or staging for further attacks.

6. 🧠 **OSINT Confirmation**  
   OSINT tools (VirusTotal, DomainTools) confirmed both the file and domain as malicious. The domain was later found unregistered, suggesting it was used temporarily and discarded—a common trait in malware campaigns.

---

✅ This was a successful forensic triage using both packet-level network analysis and open-source intelligence, resulting in full attribution of malware behavior, delivery method, and data exfiltration path. The incident highlights the importance of:
- Email filtering and sandboxing
- Network traffic monitoring
- Strong, unique passwords
- Blocking outbound SMTP where not required
Strong email filtering, endpoint protection, and NIDS/SIEM alerting would have helped mitigate this threat.

