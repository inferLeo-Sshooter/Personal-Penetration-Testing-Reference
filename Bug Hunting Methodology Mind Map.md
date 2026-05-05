# Bug Hunting Methodology Mind Map

```
Keep in mind:
1. when login, check all function, test all, take a long look, as if ur user, be user.
2. take notice at rustscan + nmap results. 
3. METHODS.
4. Testing with structure. test -> obfs -> test -> change method -> repeat. %27
5. Once get in with admin cred, skip normal user and what they can do
6. Do steps by steps as you prepare, dont skip anything

Bug Hunting Methodology
├── Mental Preparation
│   ├── Overcome Mental Hurdles
│   │   ├── Client reputation doesn't matter
│   │   ├── Pre-testing assumptions are false
│   │   ├── Size complexity can be managed
│   │   └── Software assumptions are wrong
│   ├── Truth: Every application has bugs
│   └── Mindset: "Push through barriers and hit it hard"
│
├── Pre-Analysis Phase
│   ├── Technology Identification
│   │   ├── WhatRuns / Wappalyzer / Whatweb / OXDF's Error
│   │   ├── webanalyze (CLI)
│   │   └── Document: Server, frameworks, analytics
│   ├── Application Layers Assessment
│   │   ├── Open ports & services
│   │   ├── Web hosting software
│   │   ├── Application framework
│   │   ├── Custom code
│   │   └── Libraries & integrations
│   ├── CVE & Vulnerability Scanning (Known vulns, Framework login pages, Default creds, anything related to non-custom code)
│   │   ├── Nuclei (1000+ CVEs, 500+ admin panels)
│   │   ├── Jaeles Scanner - a Comprehensive CVE library by j3ssi3jjj
│   │   ├── retire.js for Outdated libraries and frameworks
│   │   ├── Gofingerprint by Tanner Barnes
│   │   └── Custom nuclei templates
│   └── Port Scanning
│       ├── rustscan (fastest)
│       ├── naabu (simple & fast)
│       └── nmap (traditional)
│
├── Content Discovery
│   ├── Tools
│   │   ├── feroxbuster (preferred)
│   │   ├── ffuf, gobuster, wfuzz
│   │   └── Success depends on wordlists
│   ├── Wordlist Strategy
│   │   ├── Technology-specific lists (Visit wordlists.assetnote.io)
│   │   │   ├── IIS/Microsoft:
│   │   │	 |	  ├── ▲ httparchive_aspx_asp_cfm_svc_ashx_asmx_...
│   │   │	 |	  └── IIS Shortname Scanner
│   │   │   ├── PHP/CGI
│   │   │	 |	  ├── ▲ httparchive_cgi_pl_...
│   │   │	 |	  └── ▲ httparchive_php_...
│   │   │   ├── APIs
│   │   │	 |	  ├── ▲ httparchive_apiroutes_...
│   │   │	 |	  ├── ▲ swagger-wordlist.txt
│   │   │	 |	  └── Seclist: api-endpoints.txt
│   │   │   ├── Java
│   │   │	 |	  └── ▲ httparchive_jsp_jspa_do_action_...
│   │   │   └── Generic (After technology-specific testing)
│   │   │	 |	  ├── ▲ httparchive_directories_lm_...
│   │   │	 |	  ├── RAFT
│   │   │	 |	  ├── Robots Dissalowed
│   │   │	 |	  ├── https://github.com/six2dez/OneListForAll
│   │   │	 |	  └── jhaddix/content_discovery_all.txt
│   │   │   └── Others
│   │   │	 	  └── Anything in the "Technology <=> Host Mappings"
│   │   │	 	  	   ├── AEM
│   │   │	 	  	   ├── Apache
│   │   │	 	  	   ├── Cherrypy
│   │   │	 	  	   ├── Coldfusion
│   │   │	 	  	   ├── Django
│   │   │	 	  	   ├── Express
│   │   │	 	  	   ├── Flask
│   │   │	 	  	   ├── Laravel
│   │   │	 	  	   ├── Nginx
│   │   │	 	  	   ├── Rails
│   │   │	 	  	   ├── Spring
│   │   │	 	  	   ├── Symfony
│   │   │	 	  	   ├── Tomcat
│   │   │	 	  	   ├── Yii
│   │   │	 	  	   └── Zend
│   │   ├── Framework config files
│   │   └── Custom wordlists from source code: source2url by Daniel Miessler - Parses install directories for routes and endpoints
│   ├── Advanced Techniques
│   │   ├── Source code analysis (source2url)
│   │   ├── Pay or demo requests for path discovery (Paid-service type target)
│   │   ├── Docker Hub reconnaissance
│   │   ├── Custom word generation base on the words that are present in the site to build endpoints (Scavenger by /0xDexter0us/)
│   │   └── Historical content discovery
│   │		 ├── gau (Get All URLs): Pulls endpoints from Alien Vault's OTX and Wayback Archive, Provides historical representation of URLs and paths.
│   │		 └── waybackurls and wayymore: wayymore downloads every archived page from Wayback Machine. Parses them for parameters, endpoints, and links. 
│   ├── Recursion Strategy
│   │   ├── Don't stop at 401s
│   │   ├── Authorization chains break deeper
│   │   └── Example: /admin → /admin/dashboard → /admin/dashboard/users
│   ├── Mobile App Analysis
│   │   ├── APKLeaks for Android endpoints
│   │   ├── Extract API routes from APKs
│   │   └── Usually in scope even if not mentioned
│   └── Change Detection (For long-term target monitoring)
│       ├── Subscribe to newsletters
│       ├── Join affiliate programs
│       ├── Monitor conference talks
│       └── Monitor domains with changedetection.io
│
├── Application Analysis Framework
│   ├── Six Critical Questions
│   │   ├── 1. How does app pass data? (Understanding data flow)
│   │   │   ├── REST API ?
│   │   │   ├── Resource parameter and value ?
│   │   │   ├── Web services ?
│   │   │   └── Single page application with API calls ?
│   │   ├── 2. How does app reference users? (crucial for IDOR and authorization bugs)
│   │   │   ├── Cookies ?, API parameters ?
│   │   │   ├── UID ?, email ?, username ?
│   │   │   └── UUID ?, GUID ?
│   │   ├── 3. Does the Site Have Multi-tenancy or User Levels? (Most SaaS apps do)
│   │   │   ├── Admin vs regular users
│   │   │   ├── Tenant users
│   │   │   ├── View-only accounts
│   │   │   ├── Unauthenticated functions
│   │   │   └── Tool recommendation: Authorize extension for IDOR testing.
│   │   ├── 4. Does the Site Have a Unique Threat Model?
│   │   │   ├── Application-specific sensitive data (Each application has custom data to protect)
│   │   │   └── Example: Twitch stream keys
│   │   ├── 5. Has There Been Past Security Research?
│   │   │   ├── Google "[target] vulnerabilities"
│   │   │   ├── HackerOne/Bugcrowd histories
│   │   │   └── Look for regression opportunities and patch bypasses
│   │   └── 6. How Does the Application Framework Handle Vulnerability Classes?
│   │       ├── XSS protections
│   │       ├── CSRF handling
│   │       ├── Prioritize unprotected classes
│   │       └── If a framework has strong XSS protections, prioritize other vulnerability classes.
│   │
│   ├── Spidering
│   │   ├── GUI Tools
│   │   │   ├── Burp: Scan → Crawl
│   │   │   └── ZAP: Attack → Spider
│   │   └── CLI Tools
│   │       ├── hakrawler
│   │       └── gospider
│   │
│   ├── JavaScript Analysis
│   |   ├── Endpoint Extraction
│   |   │   ├── xnLinkFinder (handles inline JS)
│   |   │   ├── GAP - Burp extension that parses parameters and paths from JavaScript and adds them to your site tree.
│   |   │   └── LinkFinder (traditional) (not recommend)
│   |   ├── Minified/Obfuscated JS
│   |   │   ├── beautifier.io
│   |   │   └── Matso's dynamic recreation
│   |   └── Library Analysis
│   |       └── retire.js for outdated libs
│   |
│   ├── Parameter Analysis (Hunting Superpower)
│   │   ├── Statistical Vulnerability Mapping
│   │   │   ├── HUNT methodology (DefCon research)
│   │   │   ├── Parameters → Vulnerability classes
│   │   │   └── Example IDOR params: id, user, account, order, key
│   │   ├── Tools & Extensions
│   │   │   ├── gf with gf-patterns
│   │   │   ├── Burp Bounty ($75 paid tool)
│   │   │   └── Future: sus-params project
│   │   └── Mindset: "Target the statistically vulnerable parameters first". Also, keep an eye for jhaddix/sus_params on Github.
│   │
└── Heat Mapping (Priority Targeting)
    	├── 1. Upload Functions (Always test first)
	│     ├── Integrations (from 3rd party)
	│     │     └── XSS
	│     ├── Self Uploads
	│     │     ├── XML based (Docs / PDF)
	│     │     │     └── SSRF, XSS, XXE
	│     │     ├── Image
	│     │          └── XSS, Shell
	│     │                ├── Name
	│     │                ├── Binary header
	│     │                └── Metadata
	│     └── Where is data stored?
	│          └── S3 perms
	│
	├── 2. Content Types (Filter in Burp)
	│     ├── Look for multipart-forms (never met a secure one)
	│     │     └── Shell, Injections, ++
	│     ├── Look for content type XML
	│     │     └── XXE
	│     └── Look for content type JSON
	│           └── API vulns
	│
	├── 3. APIs
	│     ├── Hidden Methods: Test for authorization bypasses on admin methods
	│     └── Lack of auth: Check methods accessible to lower-privileged users
	│
	├── 4. Account Section
	│     ├── Profile
	│     │     └── Stored XSS
	│     ├── App Custom Fields
	│     │     └── Stored XSS, SSTI
	│     └── Integrations
	│           └── SSRF, XSS
	│
	├── 6. Errors
	│     ├── Run **Logger** in background during testing 
	│     ├── Exotic Injection, Look for exotic errors (not default application errors)
	│     ├── Investigate what triggered unusual errors
	│     └── Potential for injection points or application DoS
	│
	└── 5. Paths or URLs passed as values. Anywhere the application references paths or URLs:
	      ├── SSRF
	      ├── Redirection bugs
	      ├── Authorization issues
	      └── Filter Burp on parameters referencing paths/URLs

Methodology Principles:
├── "Content discovery leads to more bounties than anything else"
├── "Every application has bugs - push through mental barriers"
├── "Authentication unlocks the real attack surface"
├── "Statistical parameter analysis beats random fuzzing"
└── "Heat mapping focuses effort on highest probability targets"
```



