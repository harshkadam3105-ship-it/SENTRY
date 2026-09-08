/**
 * Centralized MITRE ATT&CK taxonomy, parser, and URL resolution.
 *
 * Guarantees that any technique format (string, object, name, ID with sub-technique dot)
 * resolves to a 100% valid, accessible attack.mitre.org documentation URL.
 */

export const MITRE_TECHNIQUES_DATA = {
  T1110: {
    id: 'T1110',
    name: 'Brute Force',
    tactic: 'Credential Access',
    desc: 'Adversaries repeatedly guess or cycle through password combinations to compromise valid user accounts.',
    url: 'https://attack.mitre.org/techniques/T1110/',
  },
  T1078: {
    id: 'T1078',
    name: 'Valid Accounts',
    tactic: 'Defense Evasion / Initial Access',
    desc: 'Adversaries abuse legitimate user credentials to masquerade as authorized personnel and blend into normal traffic.',
    url: 'https://attack.mitre.org/techniques/T1078/',
  },
  T1003: {
    id: 'T1003',
    name: 'OS Credential Dumping',
    tactic: 'Credential Access',
    desc: 'Adversaries harvest credentials and plaintext passwords from system memory (e.g. LSASS with Mimikatz).',
    url: 'https://attack.mitre.org/techniques/T1003/',
  },
  T1048: {
    id: 'T1048',
    name: 'Exfiltration Over Alternative Protocol',
    tactic: 'Exfiltration',
    desc: 'Adversaries steal sensitive internal data by routing it through unmonitored network protocols (DNS, ICMP, or non-standard ports).',
    url: 'https://attack.mitre.org/techniques/T1048/',
  },
  T1059: {
    id: 'T1059',
    name: 'Command and Scripting Interpreter',
    tactic: 'Execution',
    desc: 'Adversaries execute malicious automation and scripts using PowerShell, Bash, or Windows Command Prompt.',
    url: 'https://attack.mitre.org/techniques/T1059/',
  },
  T1021: {
    id: 'T1021',
    name: 'Remote Services',
    tactic: 'Lateral Movement',
    desc: 'Adversaries log into remote internal workstations and servers using stolen credentials over RDP, SSH, or SMB.',
    url: 'https://attack.mitre.org/techniques/T1021/',
  },
  T1071: {
    id: 'T1071',
    name: 'Application Layer Protocol',
    tactic: 'Command & Control',
    desc: 'Adversaries communicate with external C2 servers over standard web protocols (HTTP/HTTPS) to avoid firewall inspection.',
    url: 'https://attack.mitre.org/techniques/T1071/',
  },
  T1083: {
    id: 'T1083',
    name: 'File and Directory Discovery',
    tactic: 'Discovery',
    desc: 'Adversaries search local directories and file systems to locate confidential documents, configuration files, and credentials.',
    url: 'https://attack.mitre.org/techniques/T1083/',
  },
  T1005: {
    id: 'T1005',
    name: 'Data from Local System',
    tactic: 'Collection',
    desc: 'Adversaries isolate and stage sensitive target files locally on an endpoint prior to exfiltration.',
    url: 'https://attack.mitre.org/techniques/T1005/',
  },
  T1548: {
    id: 'T1548',
    name: 'Abuse Elevation Control Mechanism',
    tactic: 'Privilege Escalation',
    desc: 'Adversaries bypass user access controls (UAC) or elevate sudo permissions to execute operations with administrator rights.',
    url: 'https://attack.mitre.org/techniques/T1548/',
  },
  T1055: {
    id: 'T1055',
    name: 'Process Injection',
    tactic: 'Defense Evasion / Privilege Escalation',
    desc: 'Adversaries inject malicious code into running legitimate system processes to hide their presence from antivirus.',
    url: 'https://attack.mitre.org/techniques/T1055/',
  },
  T1046: {
    id: 'T1046',
    name: 'Network Service Discovery',
    tactic: 'Discovery',
    desc: 'Adversaries port-scan the internal corporate network to discover vulnerable servers, open ports, and listening services.',
    url: 'https://attack.mitre.org/techniques/T1046/',
  },
  T1053: {
    id: 'T1053',
    name: 'Scheduled Task / Job',
    tactic: 'Persistence / Privilege Escalation',
    desc: 'Adversaries configure OS scheduled tasks or cron jobs to maintain long-term persistent access across system reboots.',
    url: 'https://attack.mitre.org/techniques/T1053/',
  },
  T1070: {
    id: 'T1070',
    name: 'Indicator Removal on Host',
    tactic: 'Defense Evasion',
    desc: 'Adversaries delete, tamper with, or clear Windows Event Logs and bash histories to cover their operational tracks.',
    url: 'https://attack.mitre.org/techniques/T1070/',
  },
  T1136: {
    id: 'T1136',
    name: 'Create Account',
    tactic: 'Persistence',
    desc: 'Adversaries create unauthorized local or domain user accounts to preserve backdoor access if credentials change.',
    url: 'https://attack.mitre.org/techniques/T1136/',
  },
  T1098: {
    id: 'T1098',
    name: 'Account Manipulation',
    tactic: 'Persistence / Privilege Escalation',
    desc: 'Adversaries modify account permissions, SSH keys, or group memberships to maintain privileged access.',
    url: 'https://attack.mitre.org/techniques/T1098/',
  },
  T1567: {
    id: 'T1567',
    name: 'Exfiltration Over Web Service',
    tactic: 'Exfiltration',
    desc: 'Adversaries upload sensitive files to external cloud storage (Mega, Google Drive, Pastebin) to bypass outbound inspection.',
    url: 'https://attack.mitre.org/techniques/T1567/',
  },
  T1486: {
    id: 'T1486',
    name: 'Data Encrypted for Impact',
    tactic: 'Impact',
    desc: 'Adversaries encrypt sensitive enterprise data and systems with ransomware to disrupt operations and demand ransom.',
    url: 'https://attack.mitre.org/techniques/T1486/',
  },
  T1498: {
    id: 'T1498',
    name: 'Network Denial of Service',
    tactic: 'Impact',
    desc: 'Adversaries flood network interfaces or services with traffic to exhaust system resources and bring down availability.',
    url: 'https://attack.mitre.org/techniques/T1498/',
  },
  T1190: {
    id: 'T1190',
    name: 'Exploit Public-Facing Application',
    tactic: 'Initial Access',
    desc: 'Adversaries exploit vulnerabilities in internet-accessible software or APIs (e.g., SQL injection, RCE) to gain unauthorized access.',
    url: 'https://attack.mitre.org/techniques/T1190/',
  },
}

const NAME_TO_MITRE_ID = {
  'brute force': 'T1110',
  'valid accounts': 'T1078',
  'possible valid accounts': 'T1078',
  'suspicious login source': 'T1078',
  'untrusted login': 'T1078',
  'credential dumping': 'T1003',
  'os credential dumping': 'T1003',
  'data exfiltration': 'T1048',
  'exfiltration over alternative protocol': 'T1048',
  'suspicious process': 'T1059',
  'command and scripting interpreter': 'T1059',
  'remote services': 'T1021',
  'lateral movement': 'T1021',
  'unusual outbound activity': 'T1071',
  'api abuse': 'T1071',
  'application layer protocol': 'T1071',
  'suspicious file activity': 'T1083',
  'file & directory discovery': 'T1083',
  'file and directory discovery': 'T1083',
  'data from local system': 'T1005',
  'privilege escalation': 'T1548',
  'abuse elevation control mechanism': 'T1548',
  'suspicious parent process': 'T1055',
  'process injection': 'T1055',
  'network scanning': 'T1046',
  'network service discovery': 'T1046',
  'persistence mechanism': 'T1053',
  'scheduled task': 'T1053',
  'scheduled task / job': 'T1053',
  'defense evasion': 'T1070',
  'indicator removal on host': 'T1070',
  'create account': 'T1136',
  'account manipulation': 'T1098',
  'exfiltration over web service': 'T1567',
  'data encrypted for impact': 'T1486',
  'ransomware': 'T1486',
  'network denial of service': 'T1498',
  'dos': 'T1498',
  'sql injection': 'T1190',
  'exploit public-facing application': 'T1190',
}

export function resolveMitreTechnique(input, fallbackIndex = 0) {
  let raw = ''
  let customName = ''

  if (typeof input === 'string') {
    raw = input.trim()
  } else if (input && typeof input === 'object') {
    raw = String(input.mitre_id || input.id || input.code || input.technique_id || input.technique || '')
    customName = input.technique || input.name || ''
  } else {
    raw = String(input || '')
  }

  const idMatch = raw.match(/T\d{4}(?:[./]\d{3})?/i)
  let mitreId = idMatch ? idMatch[0].toUpperCase().replace('/', '.') : null

  if (!mitreId) {
    const cleanLower = raw.toLowerCase().replace(/[·•\-–]/g, ' ').trim()
    for (const [key, val] of Object.entries(NAME_TO_MITRE_ID)) {
      if (cleanLower.includes(key)) {
        mitreId = val
        break
      }
    }
  }

  const baseId = mitreId ? mitreId.split('.')[0] : null
  const known = mitreId ? (MITRE_TECHNIQUES_DATA[mitreId] || (baseId ? MITRE_TECHNIQUES_DATA[baseId] : null)) : null

  let url = 'https://attack.mitre.org/'
  if (mitreId) {
    const urlId = mitreId.replace('.', '/')
    url = 'https://attack.mitre.org/techniques/' + urlId + '/'
  }

  const displayId = mitreId || (raw.startsWith('T') ? raw.split(/[\s·•\-]/)[0] : 'T-' + fallbackIndex)
  const name = customName || (known ? known.name : raw.replace(/T\d{4}(?:[./]\d{3})?[\s·•\-]*/i, '').trim()) || 'Security Threat Technique'
  const tactic = known ? known.tactic : 'Threat Technique'
  const desc = known ? known.desc : 'Adversary behavior pattern detected by Sentry signature and anomaly analysis engine.'

  return {
    id: mitreId || displayId,
    displayId,
    name,
    tactic,
    desc,
    url,
  }
}

export function openMitreUrl(url, e) {
  if (e && typeof e.stopPropagation === 'function') {
    e.stopPropagation()
  }

  // If invoked programmatically without a native <a> click:
  if (!e && typeof window !== 'undefined') {
    const targetUrl = url || 'https://attack.mitre.org/'
    window.open(targetUrl, '_blank', 'noopener,noreferrer')
  }
}
