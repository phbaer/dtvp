# DTVP and Agentyzer OWASP pytm Analysis

> Generated from `threatmodel/dtvp.py`. Generated findings are review inputs,
> not accepted-risk decisions. The curated decisions and residual-risk register
> remain in `docs/threat-model.md`.

## System Description

DTVP authenticates reviewers, exchanges vulnerability information with a selected external backend, requests threat rescoring from vscorer, and delegates source analysis to Agentyzer. Agentyzer clones approved repositories, invokes a configured LLM, and performs bounded public research. External service internals are out of scope; their interfaces and the data sent to them are in scope.

## Assumptions

- **Privileged deployment operator** — The container host and Arcane or Compose operator can read mounted secrets and application volumes.
- **Approved external services** — Operators configure trusted IdP, vulnerability-backend, vscorer, Git, and LLM endpoints with normal TLS validation.
- **Single writer per local volume** — One DTVP scheduler and one Agentyzer executor operate on each local state volume.


## Trust Boundaries

- **DTVP deployment** — Operator-controlled container host and network policy.
- **DTVP service** — Authenticated vulnerability-management application.
- **Agentyzer service** — Token-authenticated source-analysis application.
- **Local state volumes** — DTVP durable state and the separately disposable Agentyzer clone cache.
- **External services** — Independently operated identity, backend, source, and AI systems.


## Components

- **DTVP ingress or reverse proxy** (`Server`) — TLS termination and host-validated routing in front of DTVP. This may be packaged nginx or an operator-managed reverse proxy.
- **DTVP API** (`Server`) — FastAPI service enforcing OIDC sessions, roles, backend namespace isolation, bounded input, audit, and integration policy.
- **Agentyzer API** (`Server`) — FastAPI service enforcing independent service/admin bearer tokens, owner scope, queue admission, and filesystem constraints.
- **Agentyzer assessment pipeline** (`Agent`) — Bounded multi-stage analysis pipeline using approved repository, research, and LLM tools; outputs require human review.
- **DTVP durable state** (`Datastore`) — Backend-scoped caches, queues, results, audits, archives, and backup-status data.
- **Disposable Agentyzer repository and job state** (`Datastore`) — Credential-free clone objects, detached worktrees, and local job records. This volume is excluded from DTVP backups.
- **OIDC identity provider** (`ExternalEntity`) — External authorization server, discovery, JWKS, and token issuer.
- **Vulnerability backend** (`ExternalEntity`) — Selected vendor-neutral backend instance providing findings, assessments, projects, and SBOM import.
- **vscorer threat-rescoring service** (`ExternalEntity`) — External tmrescore/vscorer API accepting a threat model and SBOM, then returning an immediate result or asynchronous task reference.
- **Approved Git hosts** (`ExternalEntity`) — Configured source repositories reached with child-process credentials.
- **Public research sites** (`ExternalEntity`) — Allowlisted public advisory and package metadata endpoints.
- **Configured LLM provider** (`LLM`) — Operator-approved Ollama or OpenWebUI-compatible model endpoint receiving source-derived prompts and returning untrusted output.


## Data Flows

Name | From | To | Data | Protocol | Port
--- | --- | --- | --- | --- | ---
Send authenticated browser request | Reviewer or analyst | DTVP ingress or reverse proxy | Authenticated browser request | HTTPS | 443
Return browser response | DTVP ingress or reverse proxy | Reviewer or analyst | Vulnerability and assessment data | HTTPS | 443
Forward authenticated review request | DTVP ingress or reverse proxy | DTVP API | Authenticated browser request | HTTP | 8000
Return portfolio and mutation result | DTVP API | DTVP ingress or reverse proxy | Vulnerability and assessment data | HTTP | 8000
Discover provider and exchange authorization code | DTVP API | OIDC identity provider | OIDC authorization material | HTTPS | 443
Return discovery, JWKS, and signed tokens | OIDC identity provider | DTVP API | OIDC authorization material | HTTPS | 443
Read findings and write authorized assessments | DTVP API | Vulnerability backend | Vulnerability and assessment data | HTTPS | 443
Return backend resources and mutation result | Vulnerability backend | DTVP API | Vulnerability and assessment data | HTTPS | 443
Submit threat model and SBOM for rescoring | DTVP API | vscorer threat-rescoring service | vscorer rescoring bundle | HTTPS | 443
Return immediate result or asynchronous task reference | vscorer threat-rescoring service | DTVP API | vscorer task and result | HTTPS | 443
Poll asynchronous vscorer task | DTVP API | vscorer threat-rescoring service | vscorer task and result | HTTPS | 443
Return vscorer task status or completed assessment | vscorer threat-rescoring service | DTVP API | vscorer task and result | HTTPS | 443
Submit scoped code-analysis job | DTVP API | Agentyzer API | Code-analysis request | HTTP | 8000
Return job status and analysis result | Agentyzer API | DTVP API | Agentyzer analysis result | HTTP | 8000
Dispatch admitted assessment pipeline | Agentyzer API | Agentyzer assessment pipeline | Code-analysis request | In-process | -1
Return evidence and verdict | Agentyzer assessment pipeline | Agentyzer API | Agentyzer analysis result | In-process | -1
Clone or update approved repository | Agentyzer assessment pipeline | Approved Git hosts | Repository source | Git over HTTPS or SSH | 443
Return repository objects | Approved Git hosts | Agentyzer assessment pipeline | Repository source | Git over HTTPS or SSH | 443
Fetch allowlisted public research | Agentyzer assessment pipeline | Public research sites | Public research content | HTTPS | 443
Return untrusted research content | Public research sites | Agentyzer assessment pipeline | Public research content | HTTPS | 443
Submit source-derived model prompt | Agentyzer assessment pipeline | Configured LLM provider | Source-derived LLM prompt and output | HTTP(S) OpenAI-compatible API | -1
Return untrusted model output and tool calls | Configured LLM provider | Agentyzer assessment pipeline | Source-derived LLM prompt and output | HTTP(S) OpenAI-compatible API | -1
Persist DTVP-owned state | DTVP API | DTVP durable state | Agentyzer analysis result, Vulnerability and assessment data, vscorer task and result | Local filesystem and SQLite | -1
Read DTVP-owned state | DTVP durable state | DTVP API | Agentyzer analysis result, Vulnerability and assessment data, vscorer task and result | Local filesystem and SQLite | -1
Persist disposable clones, worktrees, and job records | Agentyzer assessment pipeline | Disposable Agentyzer repository and job state | Agentyzer analysis result, Repository source | Local filesystem and SQLite | -1
Read clones and job context | Disposable Agentyzer repository and job state | Agentyzer assessment pipeline | Agentyzer analysis result, Repository source | Local filesystem and SQLite | -1


## Generated Findings


### INP03 — Server Side Include (SSI) Injection

- Target: **DTVP ingress or reverse proxy**
- Severity: **High**
- Likelihood: High

An attacker can use Server Side Include (SSI) Injection to send code to a web application that then gets executed by the web server. Doing so enables the attacker to achieve similar results to Cross Site Scripting, viz., arbitrary code execution and information disclosure, albeit on a more limited scale, since the SSI directives are nowhere near as powerful as a full-fledged scripting language. Nonetheless, the attacker can conveniently gain access to sensitive files, such as password files, and execute shell commands.

Suggested mitigations: Set the OPTIONS IncludesNOEXEC in the global access.conf file or local .htaccess (Apache) file to deny SSI execution in directories that do not need them. All user controllable input must be appropriately sanitized before use in the application. This includes omitting, or encoding, certain characters or strings that have the potential of being interpreted as part of an SSI directive. Server Side Includes must be enabled only if there is a strong business reason to do so. Every additional component enabled on the web server increases the attack surface as well as administrative overhead.

References: https://capec.mitre.org/data/definitions/101.html, http://cwe.mitre.org/data/definitions/97.html, http://cwe.mitre.org/data/definitions/74.html, http://cwe.mitre.org/data/definitions/20.html, http://cwe.mitre.org/data/definitions/713.html


### CR01 — Session Sidejacking

- Target: **DTVP ingress or reverse proxy**
- Severity: **High**
- Likelihood: High

Session sidejacking takes advantage of an unencrypted communication channel between a victim and target system. The attacker sniffs traffic on a network looking for session tokens in unencrypted traffic. Once a session token is captured, the attacker performs malicious actions by using the stolen token with the targeted application to impersonate the victim. This attack is a specific method of session hijacking, which is exploiting a valid session token to gain unauthorized access to a target system or information. Other methods to perform a session hijacking are session fixation, cross-site scripting, or compromising a user or server machine and stealing the session token.

Suggested mitigations: Make sure that HTTPS is used to communicate with the target system. Alternatively, use VPN if possible. It is important to ensure that all communication between the client and the server happens via an encrypted secure channel. Modify the session token with each transmission and protect it with cryptography. Add the idea of request sequencing that gives the server an ability to detect replay attacks.

References: https://capec.mitre.org/data/definitions/102.html, http://cwe.mitre.org/data/definitions/294.html, http://cwe.mitre.org/data/definitions/614.html, http://cwe.mitre.org/data/definitions/319.html, http://cwe.mitre.org/data/definitions/523.html, http://cwe.mitre.org/data/definitions/522.html


### DS01 — Excavation

- Target: **DTVP ingress or reverse proxy**
- Severity: **Medium**
- Likelihood: High

An adversary actively probes the target in a manner that is designed to solicit information that could be leveraged for malicious purposes. This is achieved by exploring the target via ordinary interactions for the purpose of gathering intelligence about the target, or by sending data that is syntactically invalid or non-standard in an attempt to produce a response that contains the desired data. As a result of these interactions, the adversary is able to obtain information from the target that aids the attacker in making inferences about its security, configuration, or potential vulnerabilities. Examplar exchanges with the target may trigger unhandled exceptions or verbose error messages that reveal information like stack traces, configuration information, path information, or database design. This type of attack also includes the manipulation of query strings in a URI to produce invalid SQL queries, or by trying alternative path values in the hope that the server will return useful information.

Suggested mitigations: Minimize error/response output to only what is necessary for functional use or corrective language. Remove potentially sensitive information that is not necessary for the application&#x27;s functionality.

References: https://capec.mitre.org/data/definitions/116.html, http://cwe.mitre.org/data/definitions/200.html


### DE02 — Double Encoding

- Target: **DTVP ingress or reverse proxy**
- Severity: **Medium**
- Likelihood: Low

The adversary utilizes a repeating of the encoding process for a set of characters (that is, character encoding a character encoding of a character) to obfuscate the payload of a particular request. This may allow the adversary to bypass filters that attempt to detect illegal characters or strings, such as those that might be used in traversal or injection attacks. Filters may be able to catch illegal encoded strings, but may not catch doubly encoded strings. For example, a dot (.), often used in path traversal attacks and therefore often blocked by filters, could be URL encoded as %2E. However, many filters recognize this encoding and would still block the request. In a double encoding, the % in the above URL encoding would be encoded again as %25, resulting in %252E which some filters might not catch, but which could still be interpreted as a dot (.) by interpreters on the target.

Suggested mitigations: Assume all input is malicious. Create a white list that defines all valid input to the software system based on the requirements specifications. Input that does not match against the white list should not be permitted to enter into the system. Test your decoding process against malicious input. Be aware of the threat of alternative method of data encoding and obfuscation technique such as IP address encoding. When client input is required from web-based forms, avoid using the GET method to submit data, as the method causes the form data to be appended to the URL and is easily manipulated. Instead, use the POST method whenever possible. Any security checks should occur after the data has been decoded and validated as correct data format. Do not repeat decoding process, if bad character are left after decoding process, treat the data as suspicious, and fail the validation process.Refer to the RFCs to safely decode URL. Regular expression can be used to match safe URL patterns. However, that may discard valid URL requests if the regular expression is too restrictive. There are tools to scan HTTP requests to the server for valid URL such as URLScan from Microsoft (http://www.microsoft.com/technet/security/tools/urlscan.mspx).

References: https://capec.mitre.org/data/definitions/120.html, http://cwe.mitre.org/data/definitions/173.html, http://cwe.mitre.org/data/definitions/177.html


### AC01 — Privilege Abuse

- Target: **DTVP ingress or reverse proxy**
- Severity: **Medium**
- Likelihood: 

An adversary is able to exploit features of the target that should be reserved for privileged users or administrators but are exposed to use by lower or non-privileged accounts. Access to sensitive information and functionality must be controlled to ensure that only authorized users are able to access these resources. If access control mechanisms are absent or misconfigured, a user may be able to access resources that are intended only for higher level users. An adversary may be able to exploit this to utilize a less trusted account to gain information and perform activities reserved for more trusted accounts. This attack differs from privilege escalation and other privilege stealing attacks in that the adversary never actually escalates their privileges but instead is able to use a lesser degree of privilege to access resources that should be (but are not) reserved for higher privilege accounts. Likewise, the adversary does not exploit trust or subvert systems - all control functionality is working as configured but the configuration does not adequately protect sensitive resources at an appropriate level.

Suggested mitigations: Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

References: https://capec.mitre.org/data/definitions/122.html, http://cwe.mitre.org/data/definitions/732.html, http://cwe.mitre.org/data/definitions/269.html


### DO01 — Flooding

- Target: **DTVP ingress or reverse proxy**
- Severity: **Medium**
- Likelihood: High

An adversary consumes the resources of a target by rapidly engaging in a large number of interactions with the target. This type of attack generally exposes a weakness in rate limiting or flow. When successful this attack prevents legitimate users from accessing the service and can cause the target to crash. This attack differs from resource depletion through leaks or allocations in that the latter attacks do not rely on the volume of requests made to the target but instead focus on manipulation of the target&#x27;s operations. The key factor in a flooding attack is the number of requests the adversary can make in a given period of time. The greater this number, the more likely an attack is to succeed against a given target.

Suggested mitigations: Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

References: https://capec.mitre.org/data/definitions/125.html, http://cwe.mitre.org/data/definitions/404.html, http://cwe.mitre.org/data/definitions/770.html


### DO02 — Excessive Allocation

- Target: **DTVP ingress or reverse proxy**
- Severity: **Medium**
- Likelihood: Medium

An adversary causes the target to allocate excessive resources to servicing the attackers&#x27; request, thereby reducing the resources available for legitimate services and degrading or denying services. Usually, this attack focuses on memory allocation, but any finite resource on the target could be the attacked, including bandwidth, processing cycles, or other resources. This attack does not attempt to force this allocation through a large number of requests (that would be Resource Depletion through Flooding) but instead uses one or a small number of requests that are carefully formatted to force the target to allocate excessive resources to service this request(s). Often this attack takes advantage of a bug in the target to cause the target to allocate resources vastly beyond what would be needed for a normal request.

Suggested mitigations: Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

References: https://capec.mitre.org/data/definitions/130.html, http://cwe.mitre.org/data/definitions/770.html, http://cwe.mitre.org/data/definitions/404.html


### INP08 — Format String Injection

- Target: **DTVP ingress or reverse proxy**
- Severity: **High**
- Likelihood: High

An adversary includes formatting characters in a string input field on the target application. Most applications assume that users will provide static text and may respond unpredictably to the presence of formatting character. For example, in certain functions of the C programming languages such as printf, the formatting character %s will print the contents of a memory location expecting this location to identify a string and the formatting character %n prints the number of DWORD written in the memory. An adversary can use this to read or write to memory locations or files, or simply to manipulate the value of the resulting text in unexpected ways. Reading or writing memory may result in program crashes and writing memory could result in the execution of arbitrary code if the adversary can write to the program stack.

Suggested mitigations: Limit the usage of formatting string functions. Strong input validation - All user-controllable input must be validated and filtered for illegal formatting characters.

References: https://capec.mitre.org/data/definitions/135.html, http://cwe.mitre.org/data/definitions/134.html, http://cwe.mitre.org/data/definitions/133.html


### INP11 — Relative Path Traversal

- Target: **DTVP ingress or reverse proxy**
- Severity: **High**
- Likelihood: High

An attacker exploits a weakness in input validation on the target by supplying a specially constructed path utilizing dot and slash characters for the purpose of obtaining access to arbitrary files or resources. An attacker modifies a known path on the target in order to reach material that is not available through intended channels. These attacks normally involve adding additional path separators (/ or ) and/or dots (.), or encodings thereof, in various combinations in order to reach parent directories or entirely separate trees of the target&#x27;s directory structure.

Suggested mitigations: Design: Input validation. Assume that user inputs are malicious. Utilize strict type, character, and encoding enforcement. Implementation: Perform input validation for all remote content, including remote and user-generated content. Implementation: Validate user input by only accepting known good. Ensure all content that is delivered to client is sanitized against an acceptable content specification -- whitelisting approach. Implementation: Prefer working without user input when using file system calls. Implementation: Use indirect references rather than actual file names. Implementation: Use possible permissions on file access when developing and deploying web applications.

References: https://capec.mitre.org/data/definitions/139.html, http://cwe.mitre.org/data/definitions/23.html


### CR03 — Dictionary-based Password Attack

- Target: **DTVP ingress or reverse proxy**
- Severity: **High**
- Likelihood: Medium

An attacker tries each of the words in a dictionary as passwords to gain access to the system via some user&#x27;s account. If the password chosen by the user was a word within the dictionary, this attack will be successful (in the absence of other mitigations). This is a specific instance of the password brute forcing attack pattern.

Suggested mitigations: Create a strong password policy and ensure that your system enforces this policy.Implement an intelligent password throttling mechanism. Care must be taken to assure that these mechanisms do not excessively enable account lockout attacks such as CAPEC-02.

References: https://capec.mitre.org/data/definitions/16.html, http://cwe.mitre.org/data/definitions/521.html, http://cwe.mitre.org/data/definitions/262.html, http://cwe.mitre.org/data/definitions/263.html


### HA03 — Web Application Fingerprinting

- Target: **DTVP ingress or reverse proxy**
- Severity: **Low**
- Likelihood: High

An attacker sends a series of probes to a web application in order to elicit version-dependent and type-dependent behavior that assists in identifying the target. An attacker could learn information such as software versions, error pages, and response headers, variations in implementations of the HTTP protocol, directory structures, and other similar information about the targeted service. This information can then be used by an attacker to formulate a targeted attack plan. While web application fingerprinting is not intended to be damaging (although certain activities, such as network scans, can sometimes cause disruptions to vulnerable applications inadvertently) it may often pave the way for more damaging attacks.

Suggested mitigations: Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide URL file extension.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie&#x27;s software information filed.Implementation: Appropriately deal with error messages.Implementation: Obfuscate database type in Database API&#x27;s error message.

References: https://capec.mitre.org/data/definitions/170.html, http://cwe.mitre.org/data/definitions/497.html


### SC02 — XSS Targeting Non-Script Elements

- Target: **DTVP ingress or reverse proxy**
- Severity: **Very High**
- Likelihood: High

This attack is a form of Cross-Site Scripting (XSS) where malicious scripts are embedded in elements that are not expected to host scripts such as image tags (&lt;img&gt;), comments in XML documents (&lt; !-CDATA-&gt;), etc. These tags may not be subject to the same input validation, output validation, and other content filtering and checking routines, so this can create an opportunity for an attacker to tunnel through the application&#x27;s elements and launch a XSS attack through other elements. As with all remote attacks, it is important to differentiate the ability to launch an attack (such as probing an internal network for unpatched servers) and the ability of the remote attacker to collect and interpret the output of said attack.

Suggested mitigations: In addition to the traditional input fields, all other user controllable inputs, such as image tags within messages or the likes, must also be subjected to input validation. Such validation should ensure that content that can be potentially interpreted as script by the browser is appropriately filtered.All output displayed to clients must be properly escaped. Escaping ensures that the browser interprets special scripting characters literally and not as script to be executed.

References: https://capec.mitre.org/data/definitions/18.html, http://cwe.mitre.org/data/definitions/80.html


### SC03 — Embedding Scripts within Scripts

- Target: **DTVP ingress or reverse proxy**
- Severity: **High**
- Likelihood: High

An attack of this type exploits a programs&#x27; vulnerabilities that are brought on by allowing remote hosts to execute scripts. The adversary leverages this capability to execute his/her own script by embedding it within other scripts that the target software is likely to execute. The adversary must have the ability to inject their script into a script that is likely to be executed. If this is done, then the adversary can potentially launch a variety of probes and attacks against the web server&#x27;s local environment, in many cases the so-called DMZ, back end resources the web server can communicate with, and other hosts. With the proliferation of intermediaries, such as Web App Firewalls, network devices, and even printers having JVMs and Web servers, there are many locales where an attacker can inject malicious scripts. Since this attack pattern defines scripts within scripts, there are likely privileges to execute said attack on the host. These attacks are not solely limited to the server side, client side scripts like Ajax and client side JavaScript can contain malicious scripts as well.

Suggested mitigations: Use browser technologies that do not allow client side scripting.Utilize strict type, character, and encoding enforcement.Server side developers should not proxy content via XHR or other means. If a HTTP proxy for remote content is setup on the server side, the client&#x27;s browser has no way of discerning where the data is originating from.Ensure all content that is delivered to client is sanitized against an acceptable content specification.Perform input validation for all remote content.Perform output validation for all remote content.Disable scripting languages such as JavaScript in browserSession tokens for specific hostPatching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.Privileges are constrained, if a script is loaded, ensure system runs in chroot jail or other limited authority mode

References: https://capec.mitre.org/data/definitions/19.html, http://cwe.mitre.org/data/definitions/284.html


### CR04 — Session Credential Falsification through Forging

- Target: **DTVP ingress or reverse proxy**
- Severity: **Medium**
- Likelihood: Medium

An attacker creates a false but functional session credential in order to gain or usurp access to a service. Session credentials allow users to identify themselves to a service after an initial authentication without needing to resend the authentication information (usually a username and password) with every message. If an attacker is able to forge valid session credentials they may be able to bypass authentication or piggy-back off some other authenticated user&#x27;s session. This attack differs from Reuse of Session IDs and Session Sidejacking attacks in that in the latter attacks an attacker uses a previous or existing credential without modification while, in a forging attack, the attacker must create their own credential, although it may be based on previously observed credentials.

Suggested mitigations: Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult.Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

References: https://capec.mitre.org/data/definitions/196.html, http://cwe.mitre.org/data/definitions/384.html, http://cwe.mitre.org/data/definitions/664.html


### DS04 — XSS Targeting Error Pages

- Target: **DTVP ingress or reverse proxy**
- Severity: **Medium**
- Likelihood: 

An adversary distributes a link (or possibly some other query structure) with a request to a third party web server that is malformed and also contains a block of exploit code in order to have the exploit become live code in the resulting error page. When the third party web server receives the crafted request and notes the error it then creates an error message that echoes the malformed message, including the exploit. Doing this converts the exploit portion of the message into to valid language elements that are executed by the viewing browser. When a victim executes the query provided by the attacker the infected error message error message is returned including the exploit code which then runs in the victim&#x27;s browser. XSS can result in execution of code as well as data leakage (e.g. session cookies can be sent to the attacker). This type of attack is especially dangerous since the exploit appears to come from the third party web server, who the victim may trust and hence be more vulnerable to deception.

Suggested mitigations: Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and white list any input that will be used in error messages.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

References: https://capec.mitre.org/data/definitions/198.html, http://cwe.mitre.org/data/definitions/81.html


### SC04 — XSS Using Alternate Syntax

- Target: **DTVP ingress or reverse proxy**
- Severity: **High**
- Likelihood: High

An adversary uses alternate forms of keywords or commands that result in the same action as the primary form but which may not be caught by filters. For example, many keywords are processed in a case insensitive manner. If the site&#x27;s web filtering algorithm does not convert all tags into a consistent case before the comparison with forbidden keywords it is possible to bypass filters (e.g., incomplete black lists) by using an alternate case structure. For example, the script tag using the alternate forms of Script or ScRiPt may bypass filters where script is the only form tested. Other variants using different syntax representations are also possible as well as using pollution meta-characters or entities that are eventually ignored by the rendering engine. The attack can result in the execution of otherwise prohibited functionality.

Suggested mitigations: Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcementImplementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

References: https://capec.mitre.org/data/definitions/199.html, http://cwe.mitre.org/data/definitions/87.html


### CR05 — Encryption Brute Forcing

- Target: **DTVP ingress or reverse proxy**
- Severity: **Low**
- Likelihood: Low

An attacker, armed with the cipher text and the encryption algorithm used, performs an exhaustive (brute force) search on the key space to determine the key that decrypts the cipher text to obtain the plaintext.

Suggested mitigations: Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore&#x27;s law needs to be taken into account that suggests that computing resources double every eighteen months.

References: https://capec.mitre.org/data/definitions/20.html, http://cwe.mitre.org/data/definitions/326.html, http://cwe.mitre.org/data/definitions/327.html, http://cwe.mitre.org/data/definitions/693.html, http://cwe.mitre.org/data/definitions/719.html


### SC05 — Removing Important Client Functionality

- Target: **DTVP ingress or reverse proxy**
- Severity: **High**
- Likelihood: Medium

An attacker removes or disables functionality on the client that the server assumes to be present and trustworthy. Attackers can, in some cases, get around logic put in place to &#x27;guard&#x27; sensitive functionality or data. Client applications may include functionality that a server relies on for correct and secure operation. This functionality can include, but is not limited to, filters to prevent the sending of dangerous content to the server, logical functionality such as price calculations, and authentication logic to ensure that only authorized users are utilizing the client. If an attacker can disable this functionality on the client, they can perform actions that the server believes are prohibited. This can result in client behavior that violates assumptions by the server leading to a variety of possible attacks. In the above examples, this could include the sending of dangerous content (such as scripts) to the server, incorrect price calculations, or unauthorized access to server resources.

Suggested mitigations: Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

References: http://cwe.mitre.org/data/definitions/602.html


### INP17 — XSS Using MIME Type Mismatch

- Target: **DTVP ingress or reverse proxy**
- Severity: **Medium**
- Likelihood: Medium

An adversary creates a file with scripting content but where the specified MIME type of the file is such that scripting is not expected. The adversary tricks the victim into accessing a URL that responds with the script file. Some browsers will detect that the specified MIME type of the file does not match the actual type of its content and will automatically switch to using an interpreter for the real content type. If the browser does not invoke script filters before doing this, the adversary&#x27;s script may run on the target unsanitized, possibly revealing the victim&#x27;s cookies or executing arbitrary script in their browser.

Suggested mitigations: Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

References: http://cwe.mitre.org/data/definitions/79.html, http://cwe.mitre.org/data/definitions/20.html, http://cwe.mitre.org/data/definitions/646.html


### AA03 — Exploitation of Trusted Credentials

- Target: **DTVP ingress or reverse proxy**
- Severity: **High**
- Likelihood: High

Attacks on session IDs and resource IDs take advantage of the fact that some software accepts user input without verifying its authenticity. For example, a message queuing system that allows service requesters to post messages to its queue through an open channel (such as anonymous FTP), authorization is done through checking group or role membership contained in the posted message. However, there is no proof that the message itself, the information in the message (such group or role membership), or indeed the process that wrote the message to the queue are authentic and authorized to do so. Many server side processes are vulnerable to these attacks because the server to server communications have not been analyzed from a security perspective or the processes trust other systems because they are behind a firewall. In a similar way servers that use easy to guess or spoofable schemes for representing digital identity can also be vulnerable. Such systems frequently use schemes without cryptography and digital signatures (or with broken cryptography). Session IDs may be guessed due to insufficient randomness, poor protection (passed in the clear), lack of integrity (unsigned), or improperly correlation with access control policy enforcement points. Exposed configuration and properties files that contain system passwords, database connection strings, and such may also give an attacker an edge to identify these identifiers. The net result is that spoofing and impersonation is possible leading to an attacker&#x27;s ability to break authentication, authorization, and audit controls on the system.

Suggested mitigations: Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

References: https://capec.mitre.org/data/definitions/21.html, http://cwe.mitre.org/data/definitions/290.html, http://cwe.mitre.org/data/definitions/346.html, http://cwe.mitre.org/data/definitions/664.html


### AC09 — Functionality Misuse

- Target: **DTVP ingress or reverse proxy**
- Severity: **Medium**
- Likelihood: Medium

An adversary leverages a legitimate capability of an application in such a way as to achieve a negative technical impact. The system functionality is not altered or modified but used in a way that was not intended. This is often accomplished through the overuse of a specific functionality or by leveraging functionality with design flaws that enables the adversary to gain access to unauthorized, sensitive data.

Suggested mitigations: Perform comprehensive threat modeling, a process of identifying, evaluating, and mitigating potential threats to the application. This effort can help reveal potentially obscure application functionality that can be manipulated for malicious purposes.When implementing security features, consider how they can be misused and compromised.

References: https://capec.mitre.org/data/definitions/212.html


### INP18 — Fuzzing and observing application log data/errors for application mapping

- Target: **DTVP ingress or reverse proxy**
- Severity: **Low**
- Likelihood: High

An attacker sends random, malformed, or otherwise unexpected messages to a target application and observes the application&#x27;s log or error messages returned. Fuzzing techniques involve sending random or malformed messages to a target and monitoring the target&#x27;s response. The attacker does not initially know how a target will respond to individual messages but by attempting a large number of message variants they may find a variant that trigger&#x27;s desired behavior. In this attack, the purpose of the fuzzing is to observe the application&#x27;s log and error messages, although fuzzing a target can also sometimes cause the target to enter an unstable state, causing a crash. By observing logs and error messages, the attacker can learn details about the configuration of the target application and might be able to cause the target to disclose sensitive information.

Suggested mitigations: Design: Construct a &#x27;code book&#x27; for error messages. When using a code book, application error messages aren&#x27;t generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value &#x27;coding&#x27; for the error. Such a technique will require helpdesk and hosting personnel to use a &#x27;code book&#x27; or similar mapping to decode application errors/logs in order to respond to them normally.Design: wrap application functionality (preferably through the underlying framework) in an output encoding scheme that obscures or cleanses error messages to prevent such attacks. Such a technique is often used in conjunction with the above &#x27;code book&#x27; suggestion.Implementation: Obfuscate server fields of HTTP response.Implementation: Hide inner ordering of HTTP response header.Implementation: Customizing HTTP error codes such as 404 or 500.Implementation: Hide HTTP response header software information filed.Implementation: Hide cookie&#x27;s software information filed.Implementation: Obfuscate database type in Database API&#x27;s error message.

References: https://capec.mitre.org/data/definitions/215.html, http://cwe.mitre.org/data/definitions/209.html, http://cwe.mitre.org/data/definitions/532.html


### AA04 — Exploiting Trust in Client

- Target: **DTVP ingress or reverse proxy**
- Severity: **High**
- Likelihood: High

An attack of this type exploits vulnerabilities in client/server communication channel authentication and data integrity. It leverages the implicit trust a server places in the client, or more importantly, that which the server believes is the client. An attacker executes this type of attack by placing themselves in the communication channel between client and server such that communication directly to the server is possible where the server believes it is communicating only with a valid client. There are numerous variations of this type of attack.

Suggested mitigations: Design: Ensure that client process and/or message is authenticated so that anonymous communications and/or messages are not accepted by the system.Design: Do not rely on client validation or encoding for security purposes.Design: Utilize digital signatures to increase authentication assurance.Design: Utilize two factor authentication to increase authentication assurance.Implementation: Perform input validation for all remote content.

References: https://capec.mitre.org/data/definitions/22.html, http://cwe.mitre.org/data/definitions/287.html


### INP19 — XML External Entities Blowup

- Target: **DTVP ingress or reverse proxy**
- Severity: **Medium**
- Likelihood: Low

This attack takes advantage of the entity replacement property of XML where the value of the replacement is a URI. A well-crafted XML document could have the entity refer to a URI that consumes a large amount of resources to create a denial of service condition. This can cause the system to either freeze, crash, or execute arbitrary code depending on the URI.

Suggested mitigations: This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

References: https://capec.mitre.org/data/definitions/221.html, http://cwe.mitre.org/data/definitions/611.html


### AC11 — Session Credential Falsification through Manipulation

- Target: **DTVP ingress or reverse proxy**
- Severity: **Medium**
- Likelihood: Medium

An attacker manipulates an existing credential in order to gain access to a target application. Session credentials allow users to identify themselves to a service after an initial authentication without needing to resend the authentication information (usually a username and password) with every message. An attacker may be able to manipulate a credential sniffed from an existing connection in order to gain access to a target server. For example, a credential in the form of a web cookie might have a field that indicates the access rights of a user. By manually tweaking this cookie, a user might be able to increase their access rights to the server. Alternately an attacker may be able to manipulate an existing credential to appear as a different user. This attack differs from falsification through prediction in that the user bases their modified credentials off existing credentials instead of using patterns detected in prior credentials to create a new credential that is accepted because it fits the pattern. As a result, an attacker may be able to impersonate other users or elevate their permissions to a targeted service.

Suggested mitigations: Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

References: https://capec.mitre.org/data/definitions/226.html, http://cwe.mitre.org/data/definitions/565.html, http://cwe.mitre.org/data/definitions/472.html


### INP21 — DTD Injection

- Target: **DTVP ingress or reverse proxy**
- Severity: **Medium**
- Likelihood: Medium

An attacker injects malicious content into an application&#x27;s DTD in an attempt to produce a negative technical impact. DTDs are used to describe how XML documents are processed. Certain malformed DTDs (for example, those with excessive entity expansion as described in CAPEC 197) can cause the XML parsers that process the DTDs to consume excessive resources resulting in resource depletion.

Suggested mitigations: Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

References: https://capec.mitre.org/data/definitions/228.html, http://cwe.mitre.org/data/definitions/829.html


### INP22 — XML Attribute Blowup

- Target: **DTVP ingress or reverse proxy**
- Severity: **High**
- Likelihood: High

This attack exploits certain XML parsers which manage data in an inefficient manner. The attacker crafts an XML document with many attributes in the same XML node. In a vulnerable parser, this results in a denial of service condition owhere CPU resources are exhausted because of the parsing algorithm.

Suggested mitigations: This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

References: https://capec.mitre.org/data/definitions/229.html, http://cwe.mitre.org/data/definitions/770.html


### INP28 — XSS Targeting URI Placeholders

- Target: **DTVP ingress or reverse proxy**
- Severity: **High**
- Likelihood: High

An attack of this type exploits the ability of most browsers to interpret data, javascript or other URI schemes as client-side executable content placeholders. This attack consists of passing a malicious URI in an anchor tag HREF attribute or any other similar attributes in other HTML tags. Such malicious URI contains, for example, a base64 encoded HTML content with an embedded cross-site scripting payload. The attack is executed when the browser interprets the malicious content i.e., for example, when the victim clicks on the malicious link.

Suggested mitigations: Design: Use browser technologies that do not allow client side scripting.Design: Utilize strict type, character, and encoding enforcement.Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification.Implementation: Ensure all content coming from the client is using the same encoding; if not, the server-side application must canonicalize the data before applying any filtering.Implementation: Perform input validation for all remote content, including remote and user-generated contentImplementation: Perform output validation for all remote content.Implementation: Disable scripting languages such as JavaScript in browserImplementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.

References: https://capec.mitre.org/data/definitions/244.html, http://cwe.mitre.org/data/definitions/83.html


### INP29 — XSS Using Doubled Characters

- Target: **DTVP ingress or reverse proxy**
- Severity: **Medium**
- Likelihood: Medium

The attacker bypasses input validation by using doubled characters in order to perform a cross-site scripting attack. Some filters fail to recognize dangerous sequences if they are preceded by repeated characters. For example, by doubling the &lt; before a script command, (&lt;&lt;script or %3C%3script using URI encoding) the filters of some web applications may fail to recognize the presence of a script tag. If the targeted server is vulnerable to this type of bypass, the attacker can create a crafted URL or other trap to cause a victim to view a page on the targeted server where the malicious content is executed, as per a normal XSS attack.

Suggested mitigations: Design: Use libraries and templates that minimize unfiltered input.Implementation: Normalize, filter and sanitize all user supplied fields.Implementation: The victim should configure the browser to minimize active content from untrusted sources.

References: https://capec.mitre.org/data/definitions/245.html


### INP34 — SOAP Array Overflow

- Target: **DTVP ingress or reverse proxy**
- Severity: **High**
- Likelihood: Medium

An attacker sends a SOAP request with an array whose actual length exceeds the length indicated in the request. When a data structure including a SOAP array is instantiated, the sender transmits the size of the array as an explicit parameter along with the data. If the server processing the transmission naively trusts the specified size, then an attacker can intentionally understate the size of the array, possibly resulting in a buffer overflow if the server attempts to read the entire data set into the memory it allocated for a smaller array. This, in turn, can lead to a server crash or even the execution of arbitrary code.

Suggested mitigations: If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

References: https://capec.mitre.org/data/definitions/256.html


### AC16 — Session Credential Falsification through Prediction

- Target: **DTVP ingress or reverse proxy**
- Severity: **High**
- Likelihood: High

This attack targets predictable session ID in order to gain privileges. The attacker can predict the session ID used during a transaction to perform spoofing and session hijacking.

Suggested mitigations: Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

References: https://capec.mitre.org/data/definitions/59.html


### AC17 — Session Hijacking - ServerSide

- Target: **DTVP ingress or reverse proxy**
- Severity: **Very High**
- Likelihood: High

This type of attack involves an adversary that exploits weaknesses in an application&#x27;s use of sessions in performing authentication. The advarsary is able to steal or manipulate an active session and use it to gain unathorized access to the application.

Suggested mitigations: Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

References: https://capec.mitre.org/data/definitions/593.html


### AC19 — Reusing Session IDs (aka Session Replay) - ServerSide

- Target: **DTVP ingress or reverse proxy**
- Severity: **High**
- Likelihood: High

This attack targets the reuse of valid session ID to spoof the target system in order to gain privileges. The attacker tries to reuse a stolen session ID used previously during a transaction to perform spoofing and session hijacking. Another name for this type of attack is Session Replay.

Suggested mitigations: Always invalidate a session ID after the user logout.Setup a session time out for the session IDs.Protect the communication between the client and server. For instance it is best practice to use SSL to mitigate man in the middle attack.Do not code send session ID with GET method, otherwise the session ID will be copied to the URL. In general avoid writing session IDs in the URLs. URLs can get logged in log files, which are vulnerable to an attacker.Encrypt the session data associated with the session ID.Use multifactor authentication.

References: https://capec.mitre.org/data/definitions/60.html


### CR01 — Session Sidejacking

- Target: **DTVP API**
- Severity: **High**
- Likelihood: High

Session sidejacking takes advantage of an unencrypted communication channel between a victim and target system. The attacker sniffs traffic on a network looking for session tokens in unencrypted traffic. Once a session token is captured, the attacker performs malicious actions by using the stolen token with the targeted application to impersonate the victim. This attack is a specific method of session hijacking, which is exploiting a valid session token to gain unauthorized access to a target system or information. Other methods to perform a session hijacking are session fixation, cross-site scripting, or compromising a user or server machine and stealing the session token.

Suggested mitigations: Make sure that HTTPS is used to communicate with the target system. Alternatively, use VPN if possible. It is important to ensure that all communication between the client and the server happens via an encrypted secure channel. Modify the session token with each transmission and protect it with cryptography. Add the idea of request sequencing that gives the server an ability to detect replay attacks.

References: https://capec.mitre.org/data/definitions/102.html, http://cwe.mitre.org/data/definitions/294.html, http://cwe.mitre.org/data/definitions/614.html, http://cwe.mitre.org/data/definitions/319.html, http://cwe.mitre.org/data/definitions/523.html, http://cwe.mitre.org/data/definitions/522.html


### DO01 — Flooding

- Target: **DTVP API**
- Severity: **Medium**
- Likelihood: High

An adversary consumes the resources of a target by rapidly engaging in a large number of interactions with the target. This type of attack generally exposes a weakness in rate limiting or flow. When successful this attack prevents legitimate users from accessing the service and can cause the target to crash. This attack differs from resource depletion through leaks or allocations in that the latter attacks do not rely on the volume of requests made to the target but instead focus on manipulation of the target&#x27;s operations. The key factor in a flooding attack is the number of requests the adversary can make in a given period of time. The greater this number, the more likely an attack is to succeed against a given target.

Suggested mitigations: Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

References: https://capec.mitre.org/data/definitions/125.html, http://cwe.mitre.org/data/definitions/404.html, http://cwe.mitre.org/data/definitions/770.html


### CR05 — Encryption Brute Forcing

- Target: **DTVP API**
- Severity: **Low**
- Likelihood: Low

An attacker, armed with the cipher text and the encryption algorithm used, performs an exhaustive (brute force) search on the key space to determine the key that decrypts the cipher text to obtain the plaintext.

Suggested mitigations: Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore&#x27;s law needs to be taken into account that suggests that computing resources double every eighteen months.

References: https://capec.mitre.org/data/definitions/20.html, http://cwe.mitre.org/data/definitions/326.html, http://cwe.mitre.org/data/definitions/327.html, http://cwe.mitre.org/data/definitions/693.html, http://cwe.mitre.org/data/definitions/719.html


### SC05 — Removing Important Client Functionality

- Target: **DTVP API**
- Severity: **High**
- Likelihood: Medium

An attacker removes or disables functionality on the client that the server assumes to be present and trustworthy. Attackers can, in some cases, get around logic put in place to &#x27;guard&#x27; sensitive functionality or data. Client applications may include functionality that a server relies on for correct and secure operation. This functionality can include, but is not limited to, filters to prevent the sending of dangerous content to the server, logical functionality such as price calculations, and authentication logic to ensure that only authorized users are utilizing the client. If an attacker can disable this functionality on the client, they can perform actions that the server believes are prohibited. This can result in client behavior that violates assumptions by the server leading to a variety of possible attacks. In the above examples, this could include the sending of dangerous content (such as scripts) to the server, incorrect price calculations, or unauthorized access to server resources.

Suggested mitigations: Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

References: http://cwe.mitre.org/data/definitions/602.html


### INP17 — XSS Using MIME Type Mismatch

- Target: **DTVP API**
- Severity: **Medium**
- Likelihood: Medium

An adversary creates a file with scripting content but where the specified MIME type of the file is such that scripting is not expected. The adversary tricks the victim into accessing a URL that responds with the script file. Some browsers will detect that the specified MIME type of the file does not match the actual type of its content and will automatically switch to using an interpreter for the real content type. If the browser does not invoke script filters before doing this, the adversary&#x27;s script may run on the target unsanitized, possibly revealing the victim&#x27;s cookies or executing arbitrary script in their browser.

Suggested mitigations: Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

References: http://cwe.mitre.org/data/definitions/79.html, http://cwe.mitre.org/data/definitions/20.html, http://cwe.mitre.org/data/definitions/646.html


### AA03 — Exploitation of Trusted Credentials

- Target: **DTVP API**
- Severity: **High**
- Likelihood: High

Attacks on session IDs and resource IDs take advantage of the fact that some software accepts user input without verifying its authenticity. For example, a message queuing system that allows service requesters to post messages to its queue through an open channel (such as anonymous FTP), authorization is done through checking group or role membership contained in the posted message. However, there is no proof that the message itself, the information in the message (such group or role membership), or indeed the process that wrote the message to the queue are authentic and authorized to do so. Many server side processes are vulnerable to these attacks because the server to server communications have not been analyzed from a security perspective or the processes trust other systems because they are behind a firewall. In a similar way servers that use easy to guess or spoofable schemes for representing digital identity can also be vulnerable. Such systems frequently use schemes without cryptography and digital signatures (or with broken cryptography). Session IDs may be guessed due to insufficient randomness, poor protection (passed in the clear), lack of integrity (unsigned), or improperly correlation with access control policy enforcement points. Exposed configuration and properties files that contain system passwords, database connection strings, and such may also give an attacker an edge to identify these identifiers. The net result is that spoofing and impersonation is possible leading to an attacker&#x27;s ability to break authentication, authorization, and audit controls on the system.

Suggested mitigations: Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

References: https://capec.mitre.org/data/definitions/21.html, http://cwe.mitre.org/data/definitions/290.html, http://cwe.mitre.org/data/definitions/346.html, http://cwe.mitre.org/data/definitions/664.html


### INP19 — XML External Entities Blowup

- Target: **DTVP API**
- Severity: **Medium**
- Likelihood: Low

This attack takes advantage of the entity replacement property of XML where the value of the replacement is a URI. A well-crafted XML document could have the entity refer to a URI that consumes a large amount of resources to create a denial of service condition. This can cause the system to either freeze, crash, or execute arbitrary code depending on the URI.

Suggested mitigations: This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

References: https://capec.mitre.org/data/definitions/221.html, http://cwe.mitre.org/data/definitions/611.html


### INP21 — DTD Injection

- Target: **DTVP API**
- Severity: **Medium**
- Likelihood: Medium

An attacker injects malicious content into an application&#x27;s DTD in an attempt to produce a negative technical impact. DTDs are used to describe how XML documents are processed. Certain malformed DTDs (for example, those with excessive entity expansion as described in CAPEC 197) can cause the XML parsers that process the DTDs to consume excessive resources resulting in resource depletion.

Suggested mitigations: Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

References: https://capec.mitre.org/data/definitions/228.html, http://cwe.mitre.org/data/definitions/829.html


### INP22 — XML Attribute Blowup

- Target: **DTVP API**
- Severity: **High**
- Likelihood: High

This attack exploits certain XML parsers which manage data in an inefficient manner. The attacker crafts an XML document with many attributes in the same XML node. In a vulnerable parser, this results in a denial of service condition owhere CPU resources are exhausted because of the parsing algorithm.

Suggested mitigations: This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

References: https://capec.mitre.org/data/definitions/229.html, http://cwe.mitre.org/data/definitions/770.html


### DO01 — Flooding

- Target: **Agentyzer API**
- Severity: **Medium**
- Likelihood: High

An adversary consumes the resources of a target by rapidly engaging in a large number of interactions with the target. This type of attack generally exposes a weakness in rate limiting or flow. When successful this attack prevents legitimate users from accessing the service and can cause the target to crash. This attack differs from resource depletion through leaks or allocations in that the latter attacks do not rely on the volume of requests made to the target but instead focus on manipulation of the target&#x27;s operations. The key factor in a flooding attack is the number of requests the adversary can make in a given period of time. The greater this number, the more likely an attack is to succeed against a given target.

Suggested mitigations: Ensure that protocols have specific limits of scale configured. Specify expectations for capabilities and dictate which behaviors are acceptable when resource allocation reaches limits. Uniformly throttle all requests in order to make it more difficult to consume resources more quickly than they can again be freed.

References: https://capec.mitre.org/data/definitions/125.html, http://cwe.mitre.org/data/definitions/404.html, http://cwe.mitre.org/data/definitions/770.html


### CR05 — Encryption Brute Forcing

- Target: **Agentyzer API**
- Severity: **Low**
- Likelihood: Low

An attacker, armed with the cipher text and the encryption algorithm used, performs an exhaustive (brute force) search on the key space to determine the key that decrypts the cipher text to obtain the plaintext.

Suggested mitigations: Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore&#x27;s law needs to be taken into account that suggests that computing resources double every eighteen months.

References: https://capec.mitre.org/data/definitions/20.html, http://cwe.mitre.org/data/definitions/326.html, http://cwe.mitre.org/data/definitions/327.html, http://cwe.mitre.org/data/definitions/693.html, http://cwe.mitre.org/data/definitions/719.html


### SC05 — Removing Important Client Functionality

- Target: **Agentyzer API**
- Severity: **High**
- Likelihood: Medium

An attacker removes or disables functionality on the client that the server assumes to be present and trustworthy. Attackers can, in some cases, get around logic put in place to &#x27;guard&#x27; sensitive functionality or data. Client applications may include functionality that a server relies on for correct and secure operation. This functionality can include, but is not limited to, filters to prevent the sending of dangerous content to the server, logical functionality such as price calculations, and authentication logic to ensure that only authorized users are utilizing the client. If an attacker can disable this functionality on the client, they can perform actions that the server believes are prohibited. This can result in client behavior that violates assumptions by the server leading to a variety of possible attacks. In the above examples, this could include the sending of dangerous content (such as scripts) to the server, incorrect price calculations, or unauthorized access to server resources.

Suggested mitigations: Design: For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side.Design: Ship client-side application with integrity checks (code signing) when possible.Design: Use obfuscation and other techniques to prevent reverse engineering the client code.

References: http://cwe.mitre.org/data/definitions/602.html


### INP17 — XSS Using MIME Type Mismatch

- Target: **Agentyzer API**
- Severity: **Medium**
- Likelihood: Medium

An adversary creates a file with scripting content but where the specified MIME type of the file is such that scripting is not expected. The adversary tricks the victim into accessing a URL that responds with the script file. Some browsers will detect that the specified MIME type of the file does not match the actual type of its content and will automatically switch to using an interpreter for the real content type. If the browser does not invoke script filters before doing this, the adversary&#x27;s script may run on the target unsanitized, possibly revealing the victim&#x27;s cookies or executing arbitrary script in their browser.

Suggested mitigations: Design: Browsers must invoke script filters to detect that the specified MIME type of the file matches the actual type of its content before deciding which script interpreter to use.

References: http://cwe.mitre.org/data/definitions/79.html, http://cwe.mitre.org/data/definitions/20.html, http://cwe.mitre.org/data/definitions/646.html


### AA03 — Exploitation of Trusted Credentials

- Target: **Agentyzer API**
- Severity: **High**
- Likelihood: High

Attacks on session IDs and resource IDs take advantage of the fact that some software accepts user input without verifying its authenticity. For example, a message queuing system that allows service requesters to post messages to its queue through an open channel (such as anonymous FTP), authorization is done through checking group or role membership contained in the posted message. However, there is no proof that the message itself, the information in the message (such group or role membership), or indeed the process that wrote the message to the queue are authentic and authorized to do so. Many server side processes are vulnerable to these attacks because the server to server communications have not been analyzed from a security perspective or the processes trust other systems because they are behind a firewall. In a similar way servers that use easy to guess or spoofable schemes for representing digital identity can also be vulnerable. Such systems frequently use schemes without cryptography and digital signatures (or with broken cryptography). Session IDs may be guessed due to insufficient randomness, poor protection (passed in the clear), lack of integrity (unsigned), or improperly correlation with access control policy enforcement points. Exposed configuration and properties files that contain system passwords, database connection strings, and such may also give an attacker an edge to identify these identifiers. The net result is that spoofing and impersonation is possible leading to an attacker&#x27;s ability to break authentication, authorization, and audit controls on the system.

Suggested mitigations: Design: utilize strong federated identity such as SAML to encrypt and sign identity tokens in transit.Implementation: Use industry standards session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf.Implementation: If the session identifier is used for authentication, such as in the so-called single sign on use cases, then ensure that it is protected at the same level of assurance as authentication tokens.Implementation: If the web or application server supports it, then encrypting and/or signing the session ID (such as cookie) can protect the ID if intercepted.Design: Use strong session identifiers that are protected in transit and at rest.Implementation: Utilize a session timeout for all sessions, for example 20 minutes. If the user does not explicitly logout, the server terminates their session after this period of inactivity. If the user logs back in then a new session key is generated.Implementation: Verify of authenticity of all session IDs at runtime.

References: https://capec.mitre.org/data/definitions/21.html, http://cwe.mitre.org/data/definitions/290.html, http://cwe.mitre.org/data/definitions/346.html, http://cwe.mitre.org/data/definitions/664.html


### INP19 — XML External Entities Blowup

- Target: **Agentyzer API**
- Severity: **Medium**
- Likelihood: Low

This attack takes advantage of the entity replacement property of XML where the value of the replacement is a URI. A well-crafted XML document could have the entity refer to a URI that consumes a large amount of resources to create a denial of service condition. This can cause the system to either freeze, crash, or execute arbitrary code depending on the URI.

Suggested mitigations: This attack may be mitigated by tweaking the XML parser to not resolve external entities. If external entities are needed, then implement a custom XmlResolver that has a request timeout, data retrieval limit, and restrict resources it can retrieve locally.

References: https://capec.mitre.org/data/definitions/221.html, http://cwe.mitre.org/data/definitions/611.html


### AC11 — Session Credential Falsification through Manipulation

- Target: **Agentyzer API**
- Severity: **Medium**
- Likelihood: Medium

An attacker manipulates an existing credential in order to gain access to a target application. Session credentials allow users to identify themselves to a service after an initial authentication without needing to resend the authentication information (usually a username and password) with every message. An attacker may be able to manipulate a credential sniffed from an existing connection in order to gain access to a target server. For example, a credential in the form of a web cookie might have a field that indicates the access rights of a user. By manually tweaking this cookie, a user might be able to increase their access rights to the server. Alternately an attacker may be able to manipulate an existing credential to appear as a different user. This attack differs from falsification through prediction in that the user bases their modified credentials off existing credentials instead of using patterns detected in prior credentials to create a new credential that is accepted because it fits the pattern. As a result, an attacker may be able to impersonate other users or elevate their permissions to a targeted service.

Suggested mitigations: Implementation: Use session IDs that are difficult to guess or brute-force: One way for the attackers to obtain valid session IDs is by brute-forcing or guessing them. By choosing session identifiers that are sufficiently random, brute-forcing or guessing becomes very difficult. Implementation: Regenerate and destroy session identifiers when there is a change in the level of privilege: This ensures that even though a potential victim may have followed a link with a fixated identifier, a new one is issued when the level of privilege changes.

References: https://capec.mitre.org/data/definitions/226.html, http://cwe.mitre.org/data/definitions/565.html, http://cwe.mitre.org/data/definitions/472.html


### INP21 — DTD Injection

- Target: **Agentyzer API**
- Severity: **Medium**
- Likelihood: Medium

An attacker injects malicious content into an application&#x27;s DTD in an attempt to produce a negative technical impact. DTDs are used to describe how XML documents are processed. Certain malformed DTDs (for example, those with excessive entity expansion as described in CAPEC 197) can cause the XML parsers that process the DTDs to consume excessive resources resulting in resource depletion.

Suggested mitigations: Design: Sanitize incoming DTDs to prevent excessive expansion or other actions that could result in impacts like resource depletion.Implementation: Disallow the inclusion of DTDs as part of incoming messages.Implementation: Use XML parsing tools that protect against DTD attacks.

References: https://capec.mitre.org/data/definitions/228.html, http://cwe.mitre.org/data/definitions/829.html


### INP22 — XML Attribute Blowup

- Target: **Agentyzer API**
- Severity: **High**
- Likelihood: High

This attack exploits certain XML parsers which manage data in an inefficient manner. The attacker crafts an XML document with many attributes in the same XML node. In a vulnerable parser, this results in a denial of service condition owhere CPU resources are exhausted because of the parsing algorithm.

Suggested mitigations: This attack may be mitigated completely by using a parser that is not using a vulnerable container. Mitigation may also limit the number of attributes per XML element.

References: https://capec.mitre.org/data/definitions/229.html, http://cwe.mitre.org/data/definitions/770.html


### AC16 — Session Credential Falsification through Prediction

- Target: **Agentyzer API**
- Severity: **High**
- Likelihood: High

This attack targets predictable session ID in order to gain privileges. The attacker can predict the session ID used during a transaction to perform spoofing and session hijacking.

Suggested mitigations: Use a strong source of randomness to generate a session ID.Use adequate length session IDs. Do not use information available to the user in order to generate session ID (e.g., time).Ideas for creating random numbers are offered by Eastlake [RFC1750]. Encrypt the session ID if you expose it to the user. For instance session ID can be stored in a cookie in encrypted format.

References: https://capec.mitre.org/data/definitions/59.html


### AC17 — Session Hijacking - ServerSide

- Target: **Agentyzer API**
- Severity: **Very High**
- Likelihood: High

This type of attack involves an adversary that exploits weaknesses in an application&#x27;s use of sessions in performing authentication. The advarsary is able to steal or manipulate an active session and use it to gain unathorized access to the application.

Suggested mitigations: Properly encrypt and sign identity tokens in transit, and use industry standard session key generation mechanisms that utilize high amount of entropy to generate the session key. Many standard web and application servers will perform this task on your behalf. Utilize a session timeout for all sessions. If the user does not explicitly logout, terminate their session after this period of inactivity. If the user logs back in then a new session key should be generated.

References: https://capec.mitre.org/data/definitions/593.html


### AC01 — Privilege Abuse

- Target: **DTVP durable state**
- Severity: **Medium**
- Likelihood: 

An adversary is able to exploit features of the target that should be reserved for privileged users or administrators but are exposed to use by lower or non-privileged accounts. Access to sensitive information and functionality must be controlled to ensure that only authorized users are able to access these resources. If access control mechanisms are absent or misconfigured, a user may be able to access resources that are intended only for higher level users. An adversary may be able to exploit this to utilize a less trusted account to gain information and perform activities reserved for more trusted accounts. This attack differs from privilege escalation and other privilege stealing attacks in that the adversary never actually escalates their privileges but instead is able to use a lesser degree of privilege to access resources that should be (but are not) reserved for higher privilege accounts. Likewise, the adversary does not exploit trust or subvert systems - all control functionality is working as configured but the configuration does not adequately protect sensitive resources at an appropriate level.

Suggested mitigations: Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

References: https://capec.mitre.org/data/definitions/122.html, http://cwe.mitre.org/data/definitions/732.html, http://cwe.mitre.org/data/definitions/269.html


### DO02 — Excessive Allocation

- Target: **DTVP durable state**
- Severity: **Medium**
- Likelihood: Medium

An adversary causes the target to allocate excessive resources to servicing the attackers&#x27; request, thereby reducing the resources available for legitimate services and degrading or denying services. Usually, this attack focuses on memory allocation, but any finite resource on the target could be the attacked, including bandwidth, processing cycles, or other resources. This attack does not attempt to force this allocation through a large number of requests (that would be Resource Depletion through Flooding) but instead uses one or a small number of requests that are carefully formatted to force the target to allocate excessive resources to service this request(s). Often this attack takes advantage of a bug in the target to cause the target to allocate resources vastly beyond what would be needed for a normal request.

Suggested mitigations: Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

References: https://capec.mitre.org/data/definitions/130.html, http://cwe.mitre.org/data/definitions/770.html, http://cwe.mitre.org/data/definitions/404.html


### CR05 — Encryption Brute Forcing

- Target: **DTVP durable state**
- Severity: **Low**
- Likelihood: Low

An attacker, armed with the cipher text and the encryption algorithm used, performs an exhaustive (brute force) search on the key space to determine the key that decrypts the cipher text to obtain the plaintext.

Suggested mitigations: Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore&#x27;s law needs to be taken into account that suggests that computing resources double every eighteen months.

References: https://capec.mitre.org/data/definitions/20.html, http://cwe.mitre.org/data/definitions/326.html, http://cwe.mitre.org/data/definitions/327.html, http://cwe.mitre.org/data/definitions/693.html, http://cwe.mitre.org/data/definitions/719.html


### DE04 — Audit Log Manipulation

- Target: **DTVP durable state**
- Severity: **High**
- Likelihood: High

The attacker injects, manipulates, deletes, or forges malicious log entries into the log file, in an attempt to mislead an audit of the log file or cover tracks of an attack. Due to either insufficient access controls of the log files or the logging mechanism, the attacker is able to perform such actions.

Suggested mitigations: Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

References: https://capec.mitre.org/data/definitions/268.html, https://capec.mitre.org/data/definitions/93.html


### AC01 — Privilege Abuse

- Target: **Disposable Agentyzer repository and job state**
- Severity: **Medium**
- Likelihood: 

An adversary is able to exploit features of the target that should be reserved for privileged users or administrators but are exposed to use by lower or non-privileged accounts. Access to sensitive information and functionality must be controlled to ensure that only authorized users are able to access these resources. If access control mechanisms are absent or misconfigured, a user may be able to access resources that are intended only for higher level users. An adversary may be able to exploit this to utilize a less trusted account to gain information and perform activities reserved for more trusted accounts. This attack differs from privilege escalation and other privilege stealing attacks in that the adversary never actually escalates their privileges but instead is able to use a lesser degree of privilege to access resources that should be (but are not) reserved for higher privilege accounts. Likewise, the adversary does not exploit trust or subvert systems - all control functionality is working as configured but the configuration does not adequately protect sensitive resources at an appropriate level.

Suggested mitigations: Use strong authentication and authorization mechanisms. A proven protocol is OAuth 2.0, which enables a third-party application to obtain limited access to an API.

References: https://capec.mitre.org/data/definitions/122.html, http://cwe.mitre.org/data/definitions/732.html, http://cwe.mitre.org/data/definitions/269.html


### DO02 — Excessive Allocation

- Target: **Disposable Agentyzer repository and job state**
- Severity: **Medium**
- Likelihood: Medium

An adversary causes the target to allocate excessive resources to servicing the attackers&#x27; request, thereby reducing the resources available for legitimate services and degrading or denying services. Usually, this attack focuses on memory allocation, but any finite resource on the target could be the attacked, including bandwidth, processing cycles, or other resources. This attack does not attempt to force this allocation through a large number of requests (that would be Resource Depletion through Flooding) but instead uses one or a small number of requests that are carefully formatted to force the target to allocate excessive resources to service this request(s). Often this attack takes advantage of a bug in the target to cause the target to allocate resources vastly beyond what would be needed for a normal request.

Suggested mitigations: Limit the amount of resources that are accessible to unprivileged users. Assume all input is malicious. Consider all potentially relevant properties when validating input. Consider uniformly throttling all requests in order to make it more difficult to consume resources more quickly than they can again be freed. Use resource-limiting settings, if possible.

References: https://capec.mitre.org/data/definitions/130.html, http://cwe.mitre.org/data/definitions/770.html, http://cwe.mitre.org/data/definitions/404.html


### CR05 — Encryption Brute Forcing

- Target: **Disposable Agentyzer repository and job state**
- Severity: **Low**
- Likelihood: Low

An attacker, armed with the cipher text and the encryption algorithm used, performs an exhaustive (brute force) search on the key space to determine the key that decrypts the cipher text to obtain the plaintext.

Suggested mitigations: Use commonly accepted algorithms and recommended key sizes. The key size used will depend on how important it is to keep the data confidential and for how long.In theory a brute force attack performing an exhaustive key space search will always succeed, so the goal is to have computational security. Moore&#x27;s law needs to be taken into account that suggests that computing resources double every eighteen months.

References: https://capec.mitre.org/data/definitions/20.html, http://cwe.mitre.org/data/definitions/326.html, http://cwe.mitre.org/data/definitions/327.html, http://cwe.mitre.org/data/definitions/693.html, http://cwe.mitre.org/data/definitions/719.html


### DE04 — Audit Log Manipulation

- Target: **Disposable Agentyzer repository and job state**
- Severity: **High**
- Likelihood: High

The attacker injects, manipulates, deletes, or forges malicious log entries into the log file, in an attempt to mislead an audit of the log file or cover tracks of an attack. Due to either insufficient access controls of the log files or the logging mechanism, the attacker is able to perform such actions.

Suggested mitigations: Use Principle of Least Privilege to avoid unauthorized access to log files leading to manipulation/injection on those files. Do not allow tainted data to be written in the log file without prior input validation. Whitelisting may be used to properly validate the data. Use synchronization to control the flow of execution. Use static analysis tool to identify log forging vulnerabilities. Avoid viewing logs with tools that may interpret control characters in the file, such as command-line shells.

References: https://capec.mitre.org/data/definitions/268.html, https://capec.mitre.org/data/definitions/93.html


### LLM01 — Direct Prompt Injection

- Target: **Configured LLM provider**
- Severity: **High**
- Likelihood: High

An attacker crafts malicious input prompts to manipulate the LLM into performing unintended actions, bypassing safety guidelines, or revealing sensitive information from its system prompt or training data. Without content filtering, the model is vulnerable to adversarial prompts that override its intended behavior.

Suggested mitigations: Implement input content filtering and guardrails. Use prompt engineering techniques to make the system prompt more robust against injection. Apply output validation to detect and block manipulated responses. Monitor and log prompts for anomalous patterns.

References: https://owasp.org/www-project-top-10-for-large-language-model-applications/, https://genai.owasp.org/llmrisk/llm01-prompt-injection/


### LLM03 — Sensitive Data Leakage to Third-Party Provider

- Target: **Configured LLM provider**
- Severity: **High**
- Likelihood: High

When a third-party LLM API processes personal or sensitive data without adequate confidentiality controls, there is a risk that the data is exposed to the third-party provider. The provider may log, store, or use the data for training purposes, leading to potential regulatory violations and data breaches.

Suggested mitigations: Implement data masking or anonymization before sending data to the LLM. Use contractual agreements (DPAs) with the provider. Enable opt-out of data retention and training where available. Consider self-hosted alternatives for sensitive workloads. Encrypt data in transit.

References: https://owasp.org/www-project-top-10-for-large-language-model-applications/, https://genai.owasp.org/llmrisk/llm06-sensitive-information-disclosure/


### LLM07 — Jailbreaking and Safety Bypass

- Target: **Configured LLM provider**
- Severity: **High**
- Likelihood: High

An attacker uses adversarial prompting techniques to bypass the LLM&#x27;s safety guidelines and system prompt restrictions. Without content filtering, the system prompt alone is insufficient to prevent jailbreaking, as attackers can use techniques like role-playing, encoding tricks, or multi-turn manipulation to circumvent behavioral constraints.

Suggested mitigations: Implement layered defense with both system prompts and content filtering. Use output filtering to detect and block policy-violating responses. Regularly test with adversarial prompts and update defenses. Consider using classifier models to detect jailbreaking attempts.

References: https://owasp.org/www-project-top-10-for-large-language-model-applications/, https://genai.owasp.org/llmrisk/llm01-prompt-injection/


### LLM08 — Sensitive Information Disclosure Through Output

- Target: **Configured LLM provider**
- Severity: **High**
- Likelihood: High

An LLM that processes personal data without output encoding or filtering may inadvertently include sensitive information in its responses. This can occur through memorization of training data, inclusion of context from other users&#x27; queries, or manipulation by adversarial prompts designed to extract sensitive data.

Suggested mitigations: Implement output filtering to detect and redact sensitive data patterns (PII, credentials, etc.). Use output encoding appropriate to the consumption context. Apply data loss prevention (DLP) controls on LLM outputs. Minimize the amount of sensitive data in the LLM&#x27;s context.

References: https://owasp.org/www-project-top-10-for-large-language-model-applications/, https://genai.owasp.org/llmrisk/llm06-sensitive-information-disclosure/


### DE01 — Interception

- Target: **Send authenticated browser request**
- Severity: **Medium**
- Likelihood: Medium

An adversary monitors data streams to or from the target for information gathering purposes. This attack may be undertaken to solely gather sensitive information or to support a further attack against the target. This attack pattern can involve sniffing network traffic as well as other types of data streams (e.g. radio). The adversary can attempt to initiate the establishment of a data stream, influence the nature of the data transmitted, or passively observe the communications as they unfold. In all variants of this attack, the adversary is not the intended recipient of the data stream. In contrast to other means of gathering information (e.g., targeting data leaks), the adversary must actively position himself so as to observe explicit data channels (e.g. network traffic) and read the content.

Suggested mitigations: Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

References: https://capec.mitre.org/data/definitions/117.html, http://cwe.mitre.org/data/definitions/319.html, https://cwe.mitre.org/data/definitions/299.html


### AC05 — Content Spoofing

- Target: **Send authenticated browser request**
- Severity: **Medium**
- Likelihood: Medium

An adversary modifies content to make it contain something other than what the original content producer intended while keeping the apparent source of the content unchanged. The term content spoofing is most often used to describe modification of web pages hosted by a target to display the adversary&#x27;s content instead of the owner&#x27;s content. However, any content can be spoofed, including the content of email messages, file transfers, or the content of other network communication protocols. Content can be modified at the source (e.g. modifying the source file for a web page) or in transit (e.g. intercepting and modifying a message between the sender and recipient). Usually, the adversary will attempt to hide the fact that the content has been modified, but in some cases, such as with web site defacement, this is not necessary. Content Spoofing can lead to malware exposure, financial fraud (if the content governs financial transactions), privacy violations, and other unwanted outcomes.

Suggested mitigations: Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

References: https://capec.mitre.org/data/definitions/148.html, http://cwe.mitre.org/data/definitions/345.html, https://cwe.mitre.org/data/definitions/299.html


### DE03 — Sniffing Attacks

- Target: **Send authenticated browser request**
- Severity: **Medium**
- Likelihood: 

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. The adversary may precipitate or indirectly influence the content of the observed transaction, but is never the intended recipient of the information. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient.

Suggested mitigations: Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

References: https://capec.mitre.org/data/definitions/157.html, http://cwe.mitre.org/data/definitions/311.html


### CR06 — Communication Channel Manipulation

- Target: **Send authenticated browser request**
- Severity: **High**
- Likelihood: Medium

An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.

Suggested mitigations: Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

References: https://capec.mitre.org/data/definitions/216.html


### DE03 — Sniffing Attacks

- Target: **Return browser response**
- Severity: **Medium**
- Likelihood: 

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. The adversary may precipitate or indirectly influence the content of the observed transaction, but is never the intended recipient of the information. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient.

Suggested mitigations: Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

References: https://capec.mitre.org/data/definitions/157.html, http://cwe.mitre.org/data/definitions/311.html


### CR06 — Communication Channel Manipulation

- Target: **Return browser response**
- Severity: **High**
- Likelihood: Medium

An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.

Suggested mitigations: Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

References: https://capec.mitre.org/data/definitions/216.html


### DE01 — Interception

- Target: **Forward authenticated review request**
- Severity: **Medium**
- Likelihood: Medium

An adversary monitors data streams to or from the target for information gathering purposes. This attack may be undertaken to solely gather sensitive information or to support a further attack against the target. This attack pattern can involve sniffing network traffic as well as other types of data streams (e.g. radio). The adversary can attempt to initiate the establishment of a data stream, influence the nature of the data transmitted, or passively observe the communications as they unfold. In all variants of this attack, the adversary is not the intended recipient of the data stream. In contrast to other means of gathering information (e.g., targeting data leaks), the adversary must actively position himself so as to observe explicit data channels (e.g. network traffic) and read the content.

Suggested mitigations: Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

References: https://capec.mitre.org/data/definitions/117.html, http://cwe.mitre.org/data/definitions/319.html, https://cwe.mitre.org/data/definitions/299.html


### AC05 — Content Spoofing

- Target: **Forward authenticated review request**
- Severity: **Medium**
- Likelihood: Medium

An adversary modifies content to make it contain something other than what the original content producer intended while keeping the apparent source of the content unchanged. The term content spoofing is most often used to describe modification of web pages hosted by a target to display the adversary&#x27;s content instead of the owner&#x27;s content. However, any content can be spoofed, including the content of email messages, file transfers, or the content of other network communication protocols. Content can be modified at the source (e.g. modifying the source file for a web page) or in transit (e.g. intercepting and modifying a message between the sender and recipient). Usually, the adversary will attempt to hide the fact that the content has been modified, but in some cases, such as with web site defacement, this is not necessary. Content Spoofing can lead to malware exposure, financial fraud (if the content governs financial transactions), privacy violations, and other unwanted outcomes.

Suggested mitigations: Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

References: https://capec.mitre.org/data/definitions/148.html, http://cwe.mitre.org/data/definitions/345.html, https://cwe.mitre.org/data/definitions/299.html


### DE03 — Sniffing Attacks

- Target: **Forward authenticated review request**
- Severity: **Medium**
- Likelihood: 

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. The adversary may precipitate or indirectly influence the content of the observed transaction, but is never the intended recipient of the information. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient.

Suggested mitigations: Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

References: https://capec.mitre.org/data/definitions/157.html, http://cwe.mitre.org/data/definitions/311.html


### CR06 — Communication Channel Manipulation

- Target: **Forward authenticated review request**
- Severity: **High**
- Likelihood: Medium

An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.

Suggested mitigations: Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

References: https://capec.mitre.org/data/definitions/216.html


### CR08 — Client-Server Protocol Manipulation

- Target: **Forward authenticated review request**
- Severity: **Medium**
- Likelihood: Medium

An adversary takes advantage of weaknesses in the protocol by which a client and server are communicating to perform unexpected actions. Communication protocols are necessary to transfer messages between client and server applications. Moreover, different protocols may be used for different types of interactions. For example, an authentication protocol might be used to establish the identities of the server and client while a separate messaging protocol might be used to exchange data. If there is a weakness in a protocol used by the client and server, an attacker might take advantage of this to perform various types of attacks. For example, if the attacker is able to manipulate an authentication protocol, the attacker may be able spoof other clients or servers. If the attacker is able to manipulate a messaging protocol, the may be able to read sensitive information or modify message contents. This attack is often made easier by the fact that many clients and servers support multiple protocols to perform similar roles. For example, a server might support several different authentication protocols in order to support a wide range of clients, including legacy clients. Some of the older protocols may have vulnerabilities that allow an attacker to manipulate client-server interactions.

Suggested mitigations: Use strong authentication protocols.

References: https://capec.mitre.org/data/definitions/220.html, http://cwe.mitre.org/data/definitions/757.html


### DR01 — Unprotected Sensitive Data

- Target: **Forward authenticated review request**
- Severity: **High**
- Likelihood: Low

An attacker can access data in transit or at rest that is not sufficiently protected. If an attacker can decrypt a stored password, it might be used to authenticate against different services.

Suggested mitigations: All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

References: https://cwe.mitre.org/data/definitions/311.html, https://cwe.mitre.org/data/definitions/312.html, https://cwe.mitre.org/data/definitions/916.html, https://cwe.mitre.org/data/definitions/653.html


### DE01 — Interception

- Target: **Return portfolio and mutation result**
- Severity: **Medium**
- Likelihood: Medium

An adversary monitors data streams to or from the target for information gathering purposes. This attack may be undertaken to solely gather sensitive information or to support a further attack against the target. This attack pattern can involve sniffing network traffic as well as other types of data streams (e.g. radio). The adversary can attempt to initiate the establishment of a data stream, influence the nature of the data transmitted, or passively observe the communications as they unfold. In all variants of this attack, the adversary is not the intended recipient of the data stream. In contrast to other means of gathering information (e.g., targeting data leaks), the adversary must actively position himself so as to observe explicit data channels (e.g. network traffic) and read the content.

Suggested mitigations: Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

References: https://capec.mitre.org/data/definitions/117.html, http://cwe.mitre.org/data/definitions/319.html, https://cwe.mitre.org/data/definitions/299.html


### AC05 — Content Spoofing

- Target: **Return portfolio and mutation result**
- Severity: **Medium**
- Likelihood: Medium

An adversary modifies content to make it contain something other than what the original content producer intended while keeping the apparent source of the content unchanged. The term content spoofing is most often used to describe modification of web pages hosted by a target to display the adversary&#x27;s content instead of the owner&#x27;s content. However, any content can be spoofed, including the content of email messages, file transfers, or the content of other network communication protocols. Content can be modified at the source (e.g. modifying the source file for a web page) or in transit (e.g. intercepting and modifying a message between the sender and recipient). Usually, the adversary will attempt to hide the fact that the content has been modified, but in some cases, such as with web site defacement, this is not necessary. Content Spoofing can lead to malware exposure, financial fraud (if the content governs financial transactions), privacy violations, and other unwanted outcomes.

Suggested mitigations: Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

References: https://capec.mitre.org/data/definitions/148.html, http://cwe.mitre.org/data/definitions/345.html, https://cwe.mitre.org/data/definitions/299.html


### DE03 — Sniffing Attacks

- Target: **Return portfolio and mutation result**
- Severity: **Medium**
- Likelihood: 

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. The adversary may precipitate or indirectly influence the content of the observed transaction, but is never the intended recipient of the information. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient.

Suggested mitigations: Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

References: https://capec.mitre.org/data/definitions/157.html, http://cwe.mitre.org/data/definitions/311.html


### CR06 — Communication Channel Manipulation

- Target: **Return portfolio and mutation result**
- Severity: **High**
- Likelihood: Medium

An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.

Suggested mitigations: Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

References: https://capec.mitre.org/data/definitions/216.html


### CR08 — Client-Server Protocol Manipulation

- Target: **Return portfolio and mutation result**
- Severity: **Medium**
- Likelihood: Medium

An adversary takes advantage of weaknesses in the protocol by which a client and server are communicating to perform unexpected actions. Communication protocols are necessary to transfer messages between client and server applications. Moreover, different protocols may be used for different types of interactions. For example, an authentication protocol might be used to establish the identities of the server and client while a separate messaging protocol might be used to exchange data. If there is a weakness in a protocol used by the client and server, an attacker might take advantage of this to perform various types of attacks. For example, if the attacker is able to manipulate an authentication protocol, the attacker may be able spoof other clients or servers. If the attacker is able to manipulate a messaging protocol, the may be able to read sensitive information or modify message contents. This attack is often made easier by the fact that many clients and servers support multiple protocols to perform similar roles. For example, a server might support several different authentication protocols in order to support a wide range of clients, including legacy clients. Some of the older protocols may have vulnerabilities that allow an attacker to manipulate client-server interactions.

Suggested mitigations: Use strong authentication protocols.

References: https://capec.mitre.org/data/definitions/220.html, http://cwe.mitre.org/data/definitions/757.html


### DE01 — Interception

- Target: **Discover provider and exchange authorization code**
- Severity: **Medium**
- Likelihood: Medium

An adversary monitors data streams to or from the target for information gathering purposes. This attack may be undertaken to solely gather sensitive information or to support a further attack against the target. This attack pattern can involve sniffing network traffic as well as other types of data streams (e.g. radio). The adversary can attempt to initiate the establishment of a data stream, influence the nature of the data transmitted, or passively observe the communications as they unfold. In all variants of this attack, the adversary is not the intended recipient of the data stream. In contrast to other means of gathering information (e.g., targeting data leaks), the adversary must actively position himself so as to observe explicit data channels (e.g. network traffic) and read the content.

Suggested mitigations: Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

References: https://capec.mitre.org/data/definitions/117.html, http://cwe.mitre.org/data/definitions/319.html, https://cwe.mitre.org/data/definitions/299.html


### AC05 — Content Spoofing

- Target: **Discover provider and exchange authorization code**
- Severity: **Medium**
- Likelihood: Medium

An adversary modifies content to make it contain something other than what the original content producer intended while keeping the apparent source of the content unchanged. The term content spoofing is most often used to describe modification of web pages hosted by a target to display the adversary&#x27;s content instead of the owner&#x27;s content. However, any content can be spoofed, including the content of email messages, file transfers, or the content of other network communication protocols. Content can be modified at the source (e.g. modifying the source file for a web page) or in transit (e.g. intercepting and modifying a message between the sender and recipient). Usually, the adversary will attempt to hide the fact that the content has been modified, but in some cases, such as with web site defacement, this is not necessary. Content Spoofing can lead to malware exposure, financial fraud (if the content governs financial transactions), privacy violations, and other unwanted outcomes.

Suggested mitigations: Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

References: https://capec.mitre.org/data/definitions/148.html, http://cwe.mitre.org/data/definitions/345.html, https://cwe.mitre.org/data/definitions/299.html


### DE03 — Sniffing Attacks

- Target: **Discover provider and exchange authorization code**
- Severity: **Medium**
- Likelihood: 

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. The adversary may precipitate or indirectly influence the content of the observed transaction, but is never the intended recipient of the information. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient.

Suggested mitigations: Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

References: https://capec.mitre.org/data/definitions/157.html, http://cwe.mitre.org/data/definitions/311.html


### CR06 — Communication Channel Manipulation

- Target: **Discover provider and exchange authorization code**
- Severity: **High**
- Likelihood: Medium

An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.

Suggested mitigations: Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

References: https://capec.mitre.org/data/definitions/216.html


### DE03 — Sniffing Attacks

- Target: **Return discovery, JWKS, and signed tokens**
- Severity: **Medium**
- Likelihood: 

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. The adversary may precipitate or indirectly influence the content of the observed transaction, but is never the intended recipient of the information. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient.

Suggested mitigations: Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

References: https://capec.mitre.org/data/definitions/157.html, http://cwe.mitre.org/data/definitions/311.html


### CR06 — Communication Channel Manipulation

- Target: **Return discovery, JWKS, and signed tokens**
- Severity: **High**
- Likelihood: Medium

An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.

Suggested mitigations: Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

References: https://capec.mitre.org/data/definitions/216.html


### DE01 — Interception

- Target: **Read findings and write authorized assessments**
- Severity: **Medium**
- Likelihood: Medium

An adversary monitors data streams to or from the target for information gathering purposes. This attack may be undertaken to solely gather sensitive information or to support a further attack against the target. This attack pattern can involve sniffing network traffic as well as other types of data streams (e.g. radio). The adversary can attempt to initiate the establishment of a data stream, influence the nature of the data transmitted, or passively observe the communications as they unfold. In all variants of this attack, the adversary is not the intended recipient of the data stream. In contrast to other means of gathering information (e.g., targeting data leaks), the adversary must actively position himself so as to observe explicit data channels (e.g. network traffic) and read the content.

Suggested mitigations: Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

References: https://capec.mitre.org/data/definitions/117.html, http://cwe.mitre.org/data/definitions/319.html, https://cwe.mitre.org/data/definitions/299.html


### AC05 — Content Spoofing

- Target: **Read findings and write authorized assessments**
- Severity: **Medium**
- Likelihood: Medium

An adversary modifies content to make it contain something other than what the original content producer intended while keeping the apparent source of the content unchanged. The term content spoofing is most often used to describe modification of web pages hosted by a target to display the adversary&#x27;s content instead of the owner&#x27;s content. However, any content can be spoofed, including the content of email messages, file transfers, or the content of other network communication protocols. Content can be modified at the source (e.g. modifying the source file for a web page) or in transit (e.g. intercepting and modifying a message between the sender and recipient). Usually, the adversary will attempt to hide the fact that the content has been modified, but in some cases, such as with web site defacement, this is not necessary. Content Spoofing can lead to malware exposure, financial fraud (if the content governs financial transactions), privacy violations, and other unwanted outcomes.

Suggested mitigations: Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

References: https://capec.mitre.org/data/definitions/148.html, http://cwe.mitre.org/data/definitions/345.html, https://cwe.mitre.org/data/definitions/299.html


### DE03 — Sniffing Attacks

- Target: **Read findings and write authorized assessments**
- Severity: **Medium**
- Likelihood: 

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. The adversary may precipitate or indirectly influence the content of the observed transaction, but is never the intended recipient of the information. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient.

Suggested mitigations: Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

References: https://capec.mitre.org/data/definitions/157.html, http://cwe.mitre.org/data/definitions/311.html


### CR06 — Communication Channel Manipulation

- Target: **Read findings and write authorized assessments**
- Severity: **High**
- Likelihood: Medium

An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.

Suggested mitigations: Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

References: https://capec.mitre.org/data/definitions/216.html


### DE03 — Sniffing Attacks

- Target: **Return backend resources and mutation result**
- Severity: **Medium**
- Likelihood: 

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. The adversary may precipitate or indirectly influence the content of the observed transaction, but is never the intended recipient of the information. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient.

Suggested mitigations: Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

References: https://capec.mitre.org/data/definitions/157.html, http://cwe.mitre.org/data/definitions/311.html


### CR06 — Communication Channel Manipulation

- Target: **Return backend resources and mutation result**
- Severity: **High**
- Likelihood: Medium

An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.

Suggested mitigations: Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

References: https://capec.mitre.org/data/definitions/216.html


### DE01 — Interception

- Target: **Submit threat model and SBOM for rescoring**
- Severity: **Medium**
- Likelihood: Medium

An adversary monitors data streams to or from the target for information gathering purposes. This attack may be undertaken to solely gather sensitive information or to support a further attack against the target. This attack pattern can involve sniffing network traffic as well as other types of data streams (e.g. radio). The adversary can attempt to initiate the establishment of a data stream, influence the nature of the data transmitted, or passively observe the communications as they unfold. In all variants of this attack, the adversary is not the intended recipient of the data stream. In contrast to other means of gathering information (e.g., targeting data leaks), the adversary must actively position himself so as to observe explicit data channels (e.g. network traffic) and read the content.

Suggested mitigations: Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

References: https://capec.mitre.org/data/definitions/117.html, http://cwe.mitre.org/data/definitions/319.html, https://cwe.mitre.org/data/definitions/299.html


### AC05 — Content Spoofing

- Target: **Submit threat model and SBOM for rescoring**
- Severity: **Medium**
- Likelihood: Medium

An adversary modifies content to make it contain something other than what the original content producer intended while keeping the apparent source of the content unchanged. The term content spoofing is most often used to describe modification of web pages hosted by a target to display the adversary&#x27;s content instead of the owner&#x27;s content. However, any content can be spoofed, including the content of email messages, file transfers, or the content of other network communication protocols. Content can be modified at the source (e.g. modifying the source file for a web page) or in transit (e.g. intercepting and modifying a message between the sender and recipient). Usually, the adversary will attempt to hide the fact that the content has been modified, but in some cases, such as with web site defacement, this is not necessary. Content Spoofing can lead to malware exposure, financial fraud (if the content governs financial transactions), privacy violations, and other unwanted outcomes.

Suggested mitigations: Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

References: https://capec.mitre.org/data/definitions/148.html, http://cwe.mitre.org/data/definitions/345.html, https://cwe.mitre.org/data/definitions/299.html


### DE03 — Sniffing Attacks

- Target: **Submit threat model and SBOM for rescoring**
- Severity: **Medium**
- Likelihood: 

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. The adversary may precipitate or indirectly influence the content of the observed transaction, but is never the intended recipient of the information. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient.

Suggested mitigations: Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

References: https://capec.mitre.org/data/definitions/157.html, http://cwe.mitre.org/data/definitions/311.html


### CR06 — Communication Channel Manipulation

- Target: **Submit threat model and SBOM for rescoring**
- Severity: **High**
- Likelihood: Medium

An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.

Suggested mitigations: Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

References: https://capec.mitre.org/data/definitions/216.html


### DE03 — Sniffing Attacks

- Target: **Return immediate result or asynchronous task reference**
- Severity: **Medium**
- Likelihood: 

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. The adversary may precipitate or indirectly influence the content of the observed transaction, but is never the intended recipient of the information. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient.

Suggested mitigations: Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

References: https://capec.mitre.org/data/definitions/157.html, http://cwe.mitre.org/data/definitions/311.html


### CR06 — Communication Channel Manipulation

- Target: **Return immediate result or asynchronous task reference**
- Severity: **High**
- Likelihood: Medium

An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.

Suggested mitigations: Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

References: https://capec.mitre.org/data/definitions/216.html


### DE01 — Interception

- Target: **Poll asynchronous vscorer task**
- Severity: **Medium**
- Likelihood: Medium

An adversary monitors data streams to or from the target for information gathering purposes. This attack may be undertaken to solely gather sensitive information or to support a further attack against the target. This attack pattern can involve sniffing network traffic as well as other types of data streams (e.g. radio). The adversary can attempt to initiate the establishment of a data stream, influence the nature of the data transmitted, or passively observe the communications as they unfold. In all variants of this attack, the adversary is not the intended recipient of the data stream. In contrast to other means of gathering information (e.g., targeting data leaks), the adversary must actively position himself so as to observe explicit data channels (e.g. network traffic) and read the content.

Suggested mitigations: Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

References: https://capec.mitre.org/data/definitions/117.html, http://cwe.mitre.org/data/definitions/319.html, https://cwe.mitre.org/data/definitions/299.html


### AC05 — Content Spoofing

- Target: **Poll asynchronous vscorer task**
- Severity: **Medium**
- Likelihood: Medium

An adversary modifies content to make it contain something other than what the original content producer intended while keeping the apparent source of the content unchanged. The term content spoofing is most often used to describe modification of web pages hosted by a target to display the adversary&#x27;s content instead of the owner&#x27;s content. However, any content can be spoofed, including the content of email messages, file transfers, or the content of other network communication protocols. Content can be modified at the source (e.g. modifying the source file for a web page) or in transit (e.g. intercepting and modifying a message between the sender and recipient). Usually, the adversary will attempt to hide the fact that the content has been modified, but in some cases, such as with web site defacement, this is not necessary. Content Spoofing can lead to malware exposure, financial fraud (if the content governs financial transactions), privacy violations, and other unwanted outcomes.

Suggested mitigations: Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

References: https://capec.mitre.org/data/definitions/148.html, http://cwe.mitre.org/data/definitions/345.html, https://cwe.mitre.org/data/definitions/299.html


### DE03 — Sniffing Attacks

- Target: **Poll asynchronous vscorer task**
- Severity: **Medium**
- Likelihood: 

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. The adversary may precipitate or indirectly influence the content of the observed transaction, but is never the intended recipient of the information. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient.

Suggested mitigations: Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

References: https://capec.mitre.org/data/definitions/157.html, http://cwe.mitre.org/data/definitions/311.html


### CR06 — Communication Channel Manipulation

- Target: **Poll asynchronous vscorer task**
- Severity: **High**
- Likelihood: Medium

An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.

Suggested mitigations: Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

References: https://capec.mitre.org/data/definitions/216.html


### DE03 — Sniffing Attacks

- Target: **Return vscorer task status or completed assessment**
- Severity: **Medium**
- Likelihood: 

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. The adversary may precipitate or indirectly influence the content of the observed transaction, but is never the intended recipient of the information. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient.

Suggested mitigations: Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

References: https://capec.mitre.org/data/definitions/157.html, http://cwe.mitre.org/data/definitions/311.html


### CR06 — Communication Channel Manipulation

- Target: **Return vscorer task status or completed assessment**
- Severity: **High**
- Likelihood: Medium

An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.

Suggested mitigations: Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

References: https://capec.mitre.org/data/definitions/216.html


### DE01 — Interception

- Target: **Submit scoped code-analysis job**
- Severity: **Medium**
- Likelihood: Medium

An adversary monitors data streams to or from the target for information gathering purposes. This attack may be undertaken to solely gather sensitive information or to support a further attack against the target. This attack pattern can involve sniffing network traffic as well as other types of data streams (e.g. radio). The adversary can attempt to initiate the establishment of a data stream, influence the nature of the data transmitted, or passively observe the communications as they unfold. In all variants of this attack, the adversary is not the intended recipient of the data stream. In contrast to other means of gathering information (e.g., targeting data leaks), the adversary must actively position himself so as to observe explicit data channels (e.g. network traffic) and read the content.

Suggested mitigations: Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

References: https://capec.mitre.org/data/definitions/117.html, http://cwe.mitre.org/data/definitions/319.html, https://cwe.mitre.org/data/definitions/299.html


### AC05 — Content Spoofing

- Target: **Submit scoped code-analysis job**
- Severity: **Medium**
- Likelihood: Medium

An adversary modifies content to make it contain something other than what the original content producer intended while keeping the apparent source of the content unchanged. The term content spoofing is most often used to describe modification of web pages hosted by a target to display the adversary&#x27;s content instead of the owner&#x27;s content. However, any content can be spoofed, including the content of email messages, file transfers, or the content of other network communication protocols. Content can be modified at the source (e.g. modifying the source file for a web page) or in transit (e.g. intercepting and modifying a message between the sender and recipient). Usually, the adversary will attempt to hide the fact that the content has been modified, but in some cases, such as with web site defacement, this is not necessary. Content Spoofing can lead to malware exposure, financial fraud (if the content governs financial transactions), privacy violations, and other unwanted outcomes.

Suggested mitigations: Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

References: https://capec.mitre.org/data/definitions/148.html, http://cwe.mitre.org/data/definitions/345.html, https://cwe.mitre.org/data/definitions/299.html


### DE03 — Sniffing Attacks

- Target: **Submit scoped code-analysis job**
- Severity: **Medium**
- Likelihood: 

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. The adversary may precipitate or indirectly influence the content of the observed transaction, but is never the intended recipient of the information. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient.

Suggested mitigations: Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

References: https://capec.mitre.org/data/definitions/157.html, http://cwe.mitre.org/data/definitions/311.html


### CR06 — Communication Channel Manipulation

- Target: **Submit scoped code-analysis job**
- Severity: **High**
- Likelihood: Medium

An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.

Suggested mitigations: Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

References: https://capec.mitre.org/data/definitions/216.html


### CR08 — Client-Server Protocol Manipulation

- Target: **Submit scoped code-analysis job**
- Severity: **Medium**
- Likelihood: Medium

An adversary takes advantage of weaknesses in the protocol by which a client and server are communicating to perform unexpected actions. Communication protocols are necessary to transfer messages between client and server applications. Moreover, different protocols may be used for different types of interactions. For example, an authentication protocol might be used to establish the identities of the server and client while a separate messaging protocol might be used to exchange data. If there is a weakness in a protocol used by the client and server, an attacker might take advantage of this to perform various types of attacks. For example, if the attacker is able to manipulate an authentication protocol, the attacker may be able spoof other clients or servers. If the attacker is able to manipulate a messaging protocol, the may be able to read sensitive information or modify message contents. This attack is often made easier by the fact that many clients and servers support multiple protocols to perform similar roles. For example, a server might support several different authentication protocols in order to support a wide range of clients, including legacy clients. Some of the older protocols may have vulnerabilities that allow an attacker to manipulate client-server interactions.

Suggested mitigations: Use strong authentication protocols.

References: https://capec.mitre.org/data/definitions/220.html, http://cwe.mitre.org/data/definitions/757.html


### DR01 — Unprotected Sensitive Data

- Target: **Submit scoped code-analysis job**
- Severity: **High**
- Likelihood: Low

An attacker can access data in transit or at rest that is not sufficiently protected. If an attacker can decrypt a stored password, it might be used to authenticate against different services.

Suggested mitigations: All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

References: https://cwe.mitre.org/data/definitions/311.html, https://cwe.mitre.org/data/definitions/312.html, https://cwe.mitre.org/data/definitions/916.html, https://cwe.mitre.org/data/definitions/653.html


### AC23 — Credentials Disclosure

- Target: **Submit scoped code-analysis job**
- Severity: **High**
- Likelihood: Medium

If credentials (passwords or certificates) have a long lifetime their disclosure can have severe consequences, if the credentials cannot quickly be revoked and/or rotated.

Suggested mitigations: Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

References: https://pages.nist.gov/800-63-3/sp800-63b.html#sec6


### DE01 — Interception

- Target: **Return job status and analysis result**
- Severity: **Medium**
- Likelihood: Medium

An adversary monitors data streams to or from the target for information gathering purposes. This attack may be undertaken to solely gather sensitive information or to support a further attack against the target. This attack pattern can involve sniffing network traffic as well as other types of data streams (e.g. radio). The adversary can attempt to initiate the establishment of a data stream, influence the nature of the data transmitted, or passively observe the communications as they unfold. In all variants of this attack, the adversary is not the intended recipient of the data stream. In contrast to other means of gathering information (e.g., targeting data leaks), the adversary must actively position himself so as to observe explicit data channels (e.g. network traffic) and read the content.

Suggested mitigations: Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

References: https://capec.mitre.org/data/definitions/117.html, http://cwe.mitre.org/data/definitions/319.html, https://cwe.mitre.org/data/definitions/299.html


### AC05 — Content Spoofing

- Target: **Return job status and analysis result**
- Severity: **Medium**
- Likelihood: Medium

An adversary modifies content to make it contain something other than what the original content producer intended while keeping the apparent source of the content unchanged. The term content spoofing is most often used to describe modification of web pages hosted by a target to display the adversary&#x27;s content instead of the owner&#x27;s content. However, any content can be spoofed, including the content of email messages, file transfers, or the content of other network communication protocols. Content can be modified at the source (e.g. modifying the source file for a web page) or in transit (e.g. intercepting and modifying a message between the sender and recipient). Usually, the adversary will attempt to hide the fact that the content has been modified, but in some cases, such as with web site defacement, this is not necessary. Content Spoofing can lead to malware exposure, financial fraud (if the content governs financial transactions), privacy violations, and other unwanted outcomes.

Suggested mitigations: Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

References: https://capec.mitre.org/data/definitions/148.html, http://cwe.mitre.org/data/definitions/345.html, https://cwe.mitre.org/data/definitions/299.html


### DE03 — Sniffing Attacks

- Target: **Return job status and analysis result**
- Severity: **Medium**
- Likelihood: 

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. The adversary may precipitate or indirectly influence the content of the observed transaction, but is never the intended recipient of the information. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient.

Suggested mitigations: Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

References: https://capec.mitre.org/data/definitions/157.html, http://cwe.mitre.org/data/definitions/311.html


### CR06 — Communication Channel Manipulation

- Target: **Return job status and analysis result**
- Severity: **High**
- Likelihood: Medium

An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.

Suggested mitigations: Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

References: https://capec.mitre.org/data/definitions/216.html


### CR08 — Client-Server Protocol Manipulation

- Target: **Return job status and analysis result**
- Severity: **Medium**
- Likelihood: Medium

An adversary takes advantage of weaknesses in the protocol by which a client and server are communicating to perform unexpected actions. Communication protocols are necessary to transfer messages between client and server applications. Moreover, different protocols may be used for different types of interactions. For example, an authentication protocol might be used to establish the identities of the server and client while a separate messaging protocol might be used to exchange data. If there is a weakness in a protocol used by the client and server, an attacker might take advantage of this to perform various types of attacks. For example, if the attacker is able to manipulate an authentication protocol, the attacker may be able spoof other clients or servers. If the attacker is able to manipulate a messaging protocol, the may be able to read sensitive information or modify message contents. This attack is often made easier by the fact that many clients and servers support multiple protocols to perform similar roles. For example, a server might support several different authentication protocols in order to support a wide range of clients, including legacy clients. Some of the older protocols may have vulnerabilities that allow an attacker to manipulate client-server interactions.

Suggested mitigations: Use strong authentication protocols.

References: https://capec.mitre.org/data/definitions/220.html, http://cwe.mitre.org/data/definitions/757.html


### DE01 — Interception

- Target: **Dispatch admitted assessment pipeline**
- Severity: **Medium**
- Likelihood: Medium

An adversary monitors data streams to or from the target for information gathering purposes. This attack may be undertaken to solely gather sensitive information or to support a further attack against the target. This attack pattern can involve sniffing network traffic as well as other types of data streams (e.g. radio). The adversary can attempt to initiate the establishment of a data stream, influence the nature of the data transmitted, or passively observe the communications as they unfold. In all variants of this attack, the adversary is not the intended recipient of the data stream. In contrast to other means of gathering information (e.g., targeting data leaks), the adversary must actively position himself so as to observe explicit data channels (e.g. network traffic) and read the content.

Suggested mitigations: Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

References: https://capec.mitre.org/data/definitions/117.html, http://cwe.mitre.org/data/definitions/319.html, https://cwe.mitre.org/data/definitions/299.html


### AC05 — Content Spoofing

- Target: **Dispatch admitted assessment pipeline**
- Severity: **Medium**
- Likelihood: Medium

An adversary modifies content to make it contain something other than what the original content producer intended while keeping the apparent source of the content unchanged. The term content spoofing is most often used to describe modification of web pages hosted by a target to display the adversary&#x27;s content instead of the owner&#x27;s content. However, any content can be spoofed, including the content of email messages, file transfers, or the content of other network communication protocols. Content can be modified at the source (e.g. modifying the source file for a web page) or in transit (e.g. intercepting and modifying a message between the sender and recipient). Usually, the adversary will attempt to hide the fact that the content has been modified, but in some cases, such as with web site defacement, this is not necessary. Content Spoofing can lead to malware exposure, financial fraud (if the content governs financial transactions), privacy violations, and other unwanted outcomes.

Suggested mitigations: Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

References: https://capec.mitre.org/data/definitions/148.html, http://cwe.mitre.org/data/definitions/345.html, https://cwe.mitre.org/data/definitions/299.html


### DE03 — Sniffing Attacks

- Target: **Dispatch admitted assessment pipeline**
- Severity: **Medium**
- Likelihood: 

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. The adversary may precipitate or indirectly influence the content of the observed transaction, but is never the intended recipient of the information. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient.

Suggested mitigations: Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

References: https://capec.mitre.org/data/definitions/157.html, http://cwe.mitre.org/data/definitions/311.html


### CR06 — Communication Channel Manipulation

- Target: **Dispatch admitted assessment pipeline**
- Severity: **High**
- Likelihood: Medium

An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.

Suggested mitigations: Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

References: https://capec.mitre.org/data/definitions/216.html


### CR08 — Client-Server Protocol Manipulation

- Target: **Dispatch admitted assessment pipeline**
- Severity: **Medium**
- Likelihood: Medium

An adversary takes advantage of weaknesses in the protocol by which a client and server are communicating to perform unexpected actions. Communication protocols are necessary to transfer messages between client and server applications. Moreover, different protocols may be used for different types of interactions. For example, an authentication protocol might be used to establish the identities of the server and client while a separate messaging protocol might be used to exchange data. If there is a weakness in a protocol used by the client and server, an attacker might take advantage of this to perform various types of attacks. For example, if the attacker is able to manipulate an authentication protocol, the attacker may be able spoof other clients or servers. If the attacker is able to manipulate a messaging protocol, the may be able to read sensitive information or modify message contents. This attack is often made easier by the fact that many clients and servers support multiple protocols to perform similar roles. For example, a server might support several different authentication protocols in order to support a wide range of clients, including legacy clients. Some of the older protocols may have vulnerabilities that allow an attacker to manipulate client-server interactions.

Suggested mitigations: Use strong authentication protocols.

References: https://capec.mitre.org/data/definitions/220.html, http://cwe.mitre.org/data/definitions/757.html


### DS06 — Data Leak

- Target: **Dispatch admitted assessment pipeline**
- Severity: **Very High**
- Likelihood: High

An attacker can access data in transit or at rest that is not sufficiently protected. If an attacker can decrypt a stored password, it might be used to authenticate against different services.

Suggested mitigations: All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

References: https://cwe.mitre.org/data/definitions/311.html, https://cwe.mitre.org/data/definitions/312.html, https://cwe.mitre.org/data/definitions/916.html, https://cwe.mitre.org/data/definitions/653.html


### DR01 — Unprotected Sensitive Data

- Target: **Dispatch admitted assessment pipeline**
- Severity: **High**
- Likelihood: Low

An attacker can access data in transit or at rest that is not sufficiently protected. If an attacker can decrypt a stored password, it might be used to authenticate against different services.

Suggested mitigations: All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.

References: https://cwe.mitre.org/data/definitions/311.html, https://cwe.mitre.org/data/definitions/312.html, https://cwe.mitre.org/data/definitions/916.html, https://cwe.mitre.org/data/definitions/653.html


### AC23 — Credentials Disclosure

- Target: **Dispatch admitted assessment pipeline**
- Severity: **High**
- Likelihood: Medium

If credentials (passwords or certificates) have a long lifetime their disclosure can have severe consequences, if the credentials cannot quickly be revoked and/or rotated.

Suggested mitigations: Long living credentials need to have high entropy and length to be future proof, especially if it is unknwon how long these credentials will be used. Further should there be a mechanism to revoke the credentials immediately if a disclosure is suspected. To detect disclosure of the credentials their use should be monitored for suspicions activity.

References: https://pages.nist.gov/800-63-3/sp800-63b.html#sec6


### DE01 — Interception

- Target: **Return evidence and verdict**
- Severity: **Medium**
- Likelihood: Medium

An adversary monitors data streams to or from the target for information gathering purposes. This attack may be undertaken to solely gather sensitive information or to support a further attack against the target. This attack pattern can involve sniffing network traffic as well as other types of data streams (e.g. radio). The adversary can attempt to initiate the establishment of a data stream, influence the nature of the data transmitted, or passively observe the communications as they unfold. In all variants of this attack, the adversary is not the intended recipient of the data stream. In contrast to other means of gathering information (e.g., targeting data leaks), the adversary must actively position himself so as to observe explicit data channels (e.g. network traffic) and read the content.

Suggested mitigations: Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

References: https://capec.mitre.org/data/definitions/117.html, http://cwe.mitre.org/data/definitions/319.html, https://cwe.mitre.org/data/definitions/299.html


### AC05 — Content Spoofing

- Target: **Return evidence and verdict**
- Severity: **Medium**
- Likelihood: Medium

An adversary modifies content to make it contain something other than what the original content producer intended while keeping the apparent source of the content unchanged. The term content spoofing is most often used to describe modification of web pages hosted by a target to display the adversary&#x27;s content instead of the owner&#x27;s content. However, any content can be spoofed, including the content of email messages, file transfers, or the content of other network communication protocols. Content can be modified at the source (e.g. modifying the source file for a web page) or in transit (e.g. intercepting and modifying a message between the sender and recipient). Usually, the adversary will attempt to hide the fact that the content has been modified, but in some cases, such as with web site defacement, this is not necessary. Content Spoofing can lead to malware exposure, financial fraud (if the content governs financial transactions), privacy violations, and other unwanted outcomes.

Suggested mitigations: Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

References: https://capec.mitre.org/data/definitions/148.html, http://cwe.mitre.org/data/definitions/345.html, https://cwe.mitre.org/data/definitions/299.html


### DE03 — Sniffing Attacks

- Target: **Return evidence and verdict**
- Severity: **Medium**
- Likelihood: 

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. The adversary may precipitate or indirectly influence the content of the observed transaction, but is never the intended recipient of the information. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient.

Suggested mitigations: Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

References: https://capec.mitre.org/data/definitions/157.html, http://cwe.mitre.org/data/definitions/311.html


### CR06 — Communication Channel Manipulation

- Target: **Return evidence and verdict**
- Severity: **High**
- Likelihood: Medium

An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.

Suggested mitigations: Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

References: https://capec.mitre.org/data/definitions/216.html


### CR08 — Client-Server Protocol Manipulation

- Target: **Return evidence and verdict**
- Severity: **Medium**
- Likelihood: Medium

An adversary takes advantage of weaknesses in the protocol by which a client and server are communicating to perform unexpected actions. Communication protocols are necessary to transfer messages between client and server applications. Moreover, different protocols may be used for different types of interactions. For example, an authentication protocol might be used to establish the identities of the server and client while a separate messaging protocol might be used to exchange data. If there is a weakness in a protocol used by the client and server, an attacker might take advantage of this to perform various types of attacks. For example, if the attacker is able to manipulate an authentication protocol, the attacker may be able spoof other clients or servers. If the attacker is able to manipulate a messaging protocol, the may be able to read sensitive information or modify message contents. This attack is often made easier by the fact that many clients and servers support multiple protocols to perform similar roles. For example, a server might support several different authentication protocols in order to support a wide range of clients, including legacy clients. Some of the older protocols may have vulnerabilities that allow an attacker to manipulate client-server interactions.

Suggested mitigations: Use strong authentication protocols.

References: https://capec.mitre.org/data/definitions/220.html, http://cwe.mitre.org/data/definitions/757.html


### DE01 — Interception

- Target: **Clone or update approved repository**
- Severity: **Medium**
- Likelihood: Medium

An adversary monitors data streams to or from the target for information gathering purposes. This attack may be undertaken to solely gather sensitive information or to support a further attack against the target. This attack pattern can involve sniffing network traffic as well as other types of data streams (e.g. radio). The adversary can attempt to initiate the establishment of a data stream, influence the nature of the data transmitted, or passively observe the communications as they unfold. In all variants of this attack, the adversary is not the intended recipient of the data stream. In contrast to other means of gathering information (e.g., targeting data leaks), the adversary must actively position himself so as to observe explicit data channels (e.g. network traffic) and read the content.

Suggested mitigations: Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

References: https://capec.mitre.org/data/definitions/117.html, http://cwe.mitre.org/data/definitions/319.html, https://cwe.mitre.org/data/definitions/299.html


### AC05 — Content Spoofing

- Target: **Clone or update approved repository**
- Severity: **Medium**
- Likelihood: Medium

An adversary modifies content to make it contain something other than what the original content producer intended while keeping the apparent source of the content unchanged. The term content spoofing is most often used to describe modification of web pages hosted by a target to display the adversary&#x27;s content instead of the owner&#x27;s content. However, any content can be spoofed, including the content of email messages, file transfers, or the content of other network communication protocols. Content can be modified at the source (e.g. modifying the source file for a web page) or in transit (e.g. intercepting and modifying a message between the sender and recipient). Usually, the adversary will attempt to hide the fact that the content has been modified, but in some cases, such as with web site defacement, this is not necessary. Content Spoofing can lead to malware exposure, financial fraud (if the content governs financial transactions), privacy violations, and other unwanted outcomes.

Suggested mitigations: Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

References: https://capec.mitre.org/data/definitions/148.html, http://cwe.mitre.org/data/definitions/345.html, https://cwe.mitre.org/data/definitions/299.html


### DE03 — Sniffing Attacks

- Target: **Clone or update approved repository**
- Severity: **Medium**
- Likelihood: 

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. The adversary may precipitate or indirectly influence the content of the observed transaction, but is never the intended recipient of the information. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient.

Suggested mitigations: Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

References: https://capec.mitre.org/data/definitions/157.html, http://cwe.mitre.org/data/definitions/311.html


### CR06 — Communication Channel Manipulation

- Target: **Clone or update approved repository**
- Severity: **High**
- Likelihood: Medium

An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.

Suggested mitigations: Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

References: https://capec.mitre.org/data/definitions/216.html


### DE03 — Sniffing Attacks

- Target: **Return repository objects**
- Severity: **Medium**
- Likelihood: 

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. The adversary may precipitate or indirectly influence the content of the observed transaction, but is never the intended recipient of the information. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient.

Suggested mitigations: Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

References: https://capec.mitre.org/data/definitions/157.html, http://cwe.mitre.org/data/definitions/311.html


### CR06 — Communication Channel Manipulation

- Target: **Return repository objects**
- Severity: **High**
- Likelihood: Medium

An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.

Suggested mitigations: Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

References: https://capec.mitre.org/data/definitions/216.html


### DE01 — Interception

- Target: **Fetch allowlisted public research**
- Severity: **Medium**
- Likelihood: Medium

An adversary monitors data streams to or from the target for information gathering purposes. This attack may be undertaken to solely gather sensitive information or to support a further attack against the target. This attack pattern can involve sniffing network traffic as well as other types of data streams (e.g. radio). The adversary can attempt to initiate the establishment of a data stream, influence the nature of the data transmitted, or passively observe the communications as they unfold. In all variants of this attack, the adversary is not the intended recipient of the data stream. In contrast to other means of gathering information (e.g., targeting data leaks), the adversary must actively position himself so as to observe explicit data channels (e.g. network traffic) and read the content.

Suggested mitigations: Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

References: https://capec.mitre.org/data/definitions/117.html, http://cwe.mitre.org/data/definitions/319.html, https://cwe.mitre.org/data/definitions/299.html


### AC05 — Content Spoofing

- Target: **Fetch allowlisted public research**
- Severity: **Medium**
- Likelihood: Medium

An adversary modifies content to make it contain something other than what the original content producer intended while keeping the apparent source of the content unchanged. The term content spoofing is most often used to describe modification of web pages hosted by a target to display the adversary&#x27;s content instead of the owner&#x27;s content. However, any content can be spoofed, including the content of email messages, file transfers, or the content of other network communication protocols. Content can be modified at the source (e.g. modifying the source file for a web page) or in transit (e.g. intercepting and modifying a message between the sender and recipient). Usually, the adversary will attempt to hide the fact that the content has been modified, but in some cases, such as with web site defacement, this is not necessary. Content Spoofing can lead to malware exposure, financial fraud (if the content governs financial transactions), privacy violations, and other unwanted outcomes.

Suggested mitigations: Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

References: https://capec.mitre.org/data/definitions/148.html, http://cwe.mitre.org/data/definitions/345.html, https://cwe.mitre.org/data/definitions/299.html


### DE03 — Sniffing Attacks

- Target: **Fetch allowlisted public research**
- Severity: **Medium**
- Likelihood: 

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. The adversary may precipitate or indirectly influence the content of the observed transaction, but is never the intended recipient of the information. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient.

Suggested mitigations: Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

References: https://capec.mitre.org/data/definitions/157.html, http://cwe.mitre.org/data/definitions/311.html


### CR06 — Communication Channel Manipulation

- Target: **Fetch allowlisted public research**
- Severity: **High**
- Likelihood: Medium

An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.

Suggested mitigations: Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

References: https://capec.mitre.org/data/definitions/216.html


### DE03 — Sniffing Attacks

- Target: **Return untrusted research content**
- Severity: **Medium**
- Likelihood: 

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. The adversary may precipitate or indirectly influence the content of the observed transaction, but is never the intended recipient of the information. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient.

Suggested mitigations: Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

References: https://capec.mitre.org/data/definitions/157.html, http://cwe.mitre.org/data/definitions/311.html


### CR06 — Communication Channel Manipulation

- Target: **Return untrusted research content**
- Severity: **High**
- Likelihood: Medium

An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.

Suggested mitigations: Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

References: https://capec.mitre.org/data/definitions/216.html


### DE01 — Interception

- Target: **Submit source-derived model prompt**
- Severity: **Medium**
- Likelihood: Medium

An adversary monitors data streams to or from the target for information gathering purposes. This attack may be undertaken to solely gather sensitive information or to support a further attack against the target. This attack pattern can involve sniffing network traffic as well as other types of data streams (e.g. radio). The adversary can attempt to initiate the establishment of a data stream, influence the nature of the data transmitted, or passively observe the communications as they unfold. In all variants of this attack, the adversary is not the intended recipient of the data stream. In contrast to other means of gathering information (e.g., targeting data leaks), the adversary must actively position himself so as to observe explicit data channels (e.g. network traffic) and read the content.

Suggested mitigations: Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

References: https://capec.mitre.org/data/definitions/117.html, http://cwe.mitre.org/data/definitions/319.html, https://cwe.mitre.org/data/definitions/299.html


### AC05 — Content Spoofing

- Target: **Submit source-derived model prompt**
- Severity: **Medium**
- Likelihood: Medium

An adversary modifies content to make it contain something other than what the original content producer intended while keeping the apparent source of the content unchanged. The term content spoofing is most often used to describe modification of web pages hosted by a target to display the adversary&#x27;s content instead of the owner&#x27;s content. However, any content can be spoofed, including the content of email messages, file transfers, or the content of other network communication protocols. Content can be modified at the source (e.g. modifying the source file for a web page) or in transit (e.g. intercepting and modifying a message between the sender and recipient). Usually, the adversary will attempt to hide the fact that the content has been modified, but in some cases, such as with web site defacement, this is not necessary. Content Spoofing can lead to malware exposure, financial fraud (if the content governs financial transactions), privacy violations, and other unwanted outcomes.

Suggested mitigations: Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

References: https://capec.mitre.org/data/definitions/148.html, http://cwe.mitre.org/data/definitions/345.html, https://cwe.mitre.org/data/definitions/299.html


### DE03 — Sniffing Attacks

- Target: **Submit source-derived model prompt**
- Severity: **Medium**
- Likelihood: 

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. The adversary may precipitate or indirectly influence the content of the observed transaction, but is never the intended recipient of the information. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient.

Suggested mitigations: Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

References: https://capec.mitre.org/data/definitions/157.html, http://cwe.mitre.org/data/definitions/311.html


### CR06 — Communication Channel Manipulation

- Target: **Submit source-derived model prompt**
- Severity: **High**
- Likelihood: Medium

An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.

Suggested mitigations: Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

References: https://capec.mitre.org/data/definitions/216.html


### CR08 — Client-Server Protocol Manipulation

- Target: **Submit source-derived model prompt**
- Severity: **Medium**
- Likelihood: Medium

An adversary takes advantage of weaknesses in the protocol by which a client and server are communicating to perform unexpected actions. Communication protocols are necessary to transfer messages between client and server applications. Moreover, different protocols may be used for different types of interactions. For example, an authentication protocol might be used to establish the identities of the server and client while a separate messaging protocol might be used to exchange data. If there is a weakness in a protocol used by the client and server, an attacker might take advantage of this to perform various types of attacks. For example, if the attacker is able to manipulate an authentication protocol, the attacker may be able spoof other clients or servers. If the attacker is able to manipulate a messaging protocol, the may be able to read sensitive information or modify message contents. This attack is often made easier by the fact that many clients and servers support multiple protocols to perform similar roles. For example, a server might support several different authentication protocols in order to support a wide range of clients, including legacy clients. Some of the older protocols may have vulnerabilities that allow an attacker to manipulate client-server interactions.

Suggested mitigations: Use strong authentication protocols.

References: https://capec.mitre.org/data/definitions/220.html, http://cwe.mitre.org/data/definitions/757.html


### DE01 — Interception

- Target: **Return untrusted model output and tool calls**
- Severity: **Medium**
- Likelihood: Medium

An adversary monitors data streams to or from the target for information gathering purposes. This attack may be undertaken to solely gather sensitive information or to support a further attack against the target. This attack pattern can involve sniffing network traffic as well as other types of data streams (e.g. radio). The adversary can attempt to initiate the establishment of a data stream, influence the nature of the data transmitted, or passively observe the communications as they unfold. In all variants of this attack, the adversary is not the intended recipient of the data stream. In contrast to other means of gathering information (e.g., targeting data leaks), the adversary must actively position himself so as to observe explicit data channels (e.g. network traffic) and read the content.

Suggested mitigations: Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

References: https://capec.mitre.org/data/definitions/117.html, http://cwe.mitre.org/data/definitions/319.html, https://cwe.mitre.org/data/definitions/299.html


### AC05 — Content Spoofing

- Target: **Return untrusted model output and tool calls**
- Severity: **Medium**
- Likelihood: Medium

An adversary modifies content to make it contain something other than what the original content producer intended while keeping the apparent source of the content unchanged. The term content spoofing is most often used to describe modification of web pages hosted by a target to display the adversary&#x27;s content instead of the owner&#x27;s content. However, any content can be spoofed, including the content of email messages, file transfers, or the content of other network communication protocols. Content can be modified at the source (e.g. modifying the source file for a web page) or in transit (e.g. intercepting and modifying a message between the sender and recipient). Usually, the adversary will attempt to hide the fact that the content has been modified, but in some cases, such as with web site defacement, this is not necessary. Content Spoofing can lead to malware exposure, financial fraud (if the content governs financial transactions), privacy violations, and other unwanted outcomes.

Suggested mitigations: Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

References: https://capec.mitre.org/data/definitions/148.html, http://cwe.mitre.org/data/definitions/345.html, https://cwe.mitre.org/data/definitions/299.html


### DE03 — Sniffing Attacks

- Target: **Return untrusted model output and tool calls**
- Severity: **Medium**
- Likelihood: 

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. The adversary may precipitate or indirectly influence the content of the observed transaction, but is never the intended recipient of the information. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient.

Suggested mitigations: Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

References: https://capec.mitre.org/data/definitions/157.html, http://cwe.mitre.org/data/definitions/311.html


### CR06 — Communication Channel Manipulation

- Target: **Return untrusted model output and tool calls**
- Severity: **High**
- Likelihood: Medium

An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.

Suggested mitigations: Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

References: https://capec.mitre.org/data/definitions/216.html


### CR08 — Client-Server Protocol Manipulation

- Target: **Return untrusted model output and tool calls**
- Severity: **Medium**
- Likelihood: Medium

An adversary takes advantage of weaknesses in the protocol by which a client and server are communicating to perform unexpected actions. Communication protocols are necessary to transfer messages between client and server applications. Moreover, different protocols may be used for different types of interactions. For example, an authentication protocol might be used to establish the identities of the server and client while a separate messaging protocol might be used to exchange data. If there is a weakness in a protocol used by the client and server, an attacker might take advantage of this to perform various types of attacks. For example, if the attacker is able to manipulate an authentication protocol, the attacker may be able spoof other clients or servers. If the attacker is able to manipulate a messaging protocol, the may be able to read sensitive information or modify message contents. This attack is often made easier by the fact that many clients and servers support multiple protocols to perform similar roles. For example, a server might support several different authentication protocols in order to support a wide range of clients, including legacy clients. Some of the older protocols may have vulnerabilities that allow an attacker to manipulate client-server interactions.

Suggested mitigations: Use strong authentication protocols.

References: https://capec.mitre.org/data/definitions/220.html, http://cwe.mitre.org/data/definitions/757.html


### DE01 — Interception

- Target: **Persist DTVP-owned state**
- Severity: **Medium**
- Likelihood: Medium

An adversary monitors data streams to or from the target for information gathering purposes. This attack may be undertaken to solely gather sensitive information or to support a further attack against the target. This attack pattern can involve sniffing network traffic as well as other types of data streams (e.g. radio). The adversary can attempt to initiate the establishment of a data stream, influence the nature of the data transmitted, or passively observe the communications as they unfold. In all variants of this attack, the adversary is not the intended recipient of the data stream. In contrast to other means of gathering information (e.g., targeting data leaks), the adversary must actively position himself so as to observe explicit data channels (e.g. network traffic) and read the content.

Suggested mitigations: Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

References: https://capec.mitre.org/data/definitions/117.html, http://cwe.mitre.org/data/definitions/319.html, https://cwe.mitre.org/data/definitions/299.html


### AC05 — Content Spoofing

- Target: **Persist DTVP-owned state**
- Severity: **Medium**
- Likelihood: Medium

An adversary modifies content to make it contain something other than what the original content producer intended while keeping the apparent source of the content unchanged. The term content spoofing is most often used to describe modification of web pages hosted by a target to display the adversary&#x27;s content instead of the owner&#x27;s content. However, any content can be spoofed, including the content of email messages, file transfers, or the content of other network communication protocols. Content can be modified at the source (e.g. modifying the source file for a web page) or in transit (e.g. intercepting and modifying a message between the sender and recipient). Usually, the adversary will attempt to hide the fact that the content has been modified, but in some cases, such as with web site defacement, this is not necessary. Content Spoofing can lead to malware exposure, financial fraud (if the content governs financial transactions), privacy violations, and other unwanted outcomes.

Suggested mitigations: Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

References: https://capec.mitre.org/data/definitions/148.html, http://cwe.mitre.org/data/definitions/345.html, https://cwe.mitre.org/data/definitions/299.html


### DE03 — Sniffing Attacks

- Target: **Persist DTVP-owned state**
- Severity: **Medium**
- Likelihood: 

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. The adversary may precipitate or indirectly influence the content of the observed transaction, but is never the intended recipient of the information. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient.

Suggested mitigations: Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

References: https://capec.mitre.org/data/definitions/157.html, http://cwe.mitre.org/data/definitions/311.html


### CR06 — Communication Channel Manipulation

- Target: **Persist DTVP-owned state**
- Severity: **High**
- Likelihood: Medium

An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.

Suggested mitigations: Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

References: https://capec.mitre.org/data/definitions/216.html


### CR08 — Client-Server Protocol Manipulation

- Target: **Persist DTVP-owned state**
- Severity: **Medium**
- Likelihood: Medium

An adversary takes advantage of weaknesses in the protocol by which a client and server are communicating to perform unexpected actions. Communication protocols are necessary to transfer messages between client and server applications. Moreover, different protocols may be used for different types of interactions. For example, an authentication protocol might be used to establish the identities of the server and client while a separate messaging protocol might be used to exchange data. If there is a weakness in a protocol used by the client and server, an attacker might take advantage of this to perform various types of attacks. For example, if the attacker is able to manipulate an authentication protocol, the attacker may be able spoof other clients or servers. If the attacker is able to manipulate a messaging protocol, the may be able to read sensitive information or modify message contents. This attack is often made easier by the fact that many clients and servers support multiple protocols to perform similar roles. For example, a server might support several different authentication protocols in order to support a wide range of clients, including legacy clients. Some of the older protocols may have vulnerabilities that allow an attacker to manipulate client-server interactions.

Suggested mitigations: Use strong authentication protocols.

References: https://capec.mitre.org/data/definitions/220.html, http://cwe.mitre.org/data/definitions/757.html


### DE01 — Interception

- Target: **Read DTVP-owned state**
- Severity: **Medium**
- Likelihood: Medium

An adversary monitors data streams to or from the target for information gathering purposes. This attack may be undertaken to solely gather sensitive information or to support a further attack against the target. This attack pattern can involve sniffing network traffic as well as other types of data streams (e.g. radio). The adversary can attempt to initiate the establishment of a data stream, influence the nature of the data transmitted, or passively observe the communications as they unfold. In all variants of this attack, the adversary is not the intended recipient of the data stream. In contrast to other means of gathering information (e.g., targeting data leaks), the adversary must actively position himself so as to observe explicit data channels (e.g. network traffic) and read the content.

Suggested mitigations: Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

References: https://capec.mitre.org/data/definitions/117.html, http://cwe.mitre.org/data/definitions/319.html, https://cwe.mitre.org/data/definitions/299.html


### AC05 — Content Spoofing

- Target: **Read DTVP-owned state**
- Severity: **Medium**
- Likelihood: Medium

An adversary modifies content to make it contain something other than what the original content producer intended while keeping the apparent source of the content unchanged. The term content spoofing is most often used to describe modification of web pages hosted by a target to display the adversary&#x27;s content instead of the owner&#x27;s content. However, any content can be spoofed, including the content of email messages, file transfers, or the content of other network communication protocols. Content can be modified at the source (e.g. modifying the source file for a web page) or in transit (e.g. intercepting and modifying a message between the sender and recipient). Usually, the adversary will attempt to hide the fact that the content has been modified, but in some cases, such as with web site defacement, this is not necessary. Content Spoofing can lead to malware exposure, financial fraud (if the content governs financial transactions), privacy violations, and other unwanted outcomes.

Suggested mitigations: Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

References: https://capec.mitre.org/data/definitions/148.html, http://cwe.mitre.org/data/definitions/345.html, https://cwe.mitre.org/data/definitions/299.html


### DE03 — Sniffing Attacks

- Target: **Read DTVP-owned state**
- Severity: **Medium**
- Likelihood: 

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. The adversary may precipitate or indirectly influence the content of the observed transaction, but is never the intended recipient of the information. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient.

Suggested mitigations: Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

References: https://capec.mitre.org/data/definitions/157.html, http://cwe.mitre.org/data/definitions/311.html


### CR06 — Communication Channel Manipulation

- Target: **Read DTVP-owned state**
- Severity: **High**
- Likelihood: Medium

An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.

Suggested mitigations: Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

References: https://capec.mitre.org/data/definitions/216.html


### CR08 — Client-Server Protocol Manipulation

- Target: **Read DTVP-owned state**
- Severity: **Medium**
- Likelihood: Medium

An adversary takes advantage of weaknesses in the protocol by which a client and server are communicating to perform unexpected actions. Communication protocols are necessary to transfer messages between client and server applications. Moreover, different protocols may be used for different types of interactions. For example, an authentication protocol might be used to establish the identities of the server and client while a separate messaging protocol might be used to exchange data. If there is a weakness in a protocol used by the client and server, an attacker might take advantage of this to perform various types of attacks. For example, if the attacker is able to manipulate an authentication protocol, the attacker may be able spoof other clients or servers. If the attacker is able to manipulate a messaging protocol, the may be able to read sensitive information or modify message contents. This attack is often made easier by the fact that many clients and servers support multiple protocols to perform similar roles. For example, a server might support several different authentication protocols in order to support a wide range of clients, including legacy clients. Some of the older protocols may have vulnerabilities that allow an attacker to manipulate client-server interactions.

Suggested mitigations: Use strong authentication protocols.

References: https://capec.mitre.org/data/definitions/220.html, http://cwe.mitre.org/data/definitions/757.html


### DE01 — Interception

- Target: **Persist disposable clones, worktrees, and job records**
- Severity: **Medium**
- Likelihood: Medium

An adversary monitors data streams to or from the target for information gathering purposes. This attack may be undertaken to solely gather sensitive information or to support a further attack against the target. This attack pattern can involve sniffing network traffic as well as other types of data streams (e.g. radio). The adversary can attempt to initiate the establishment of a data stream, influence the nature of the data transmitted, or passively observe the communications as they unfold. In all variants of this attack, the adversary is not the intended recipient of the data stream. In contrast to other means of gathering information (e.g., targeting data leaks), the adversary must actively position himself so as to observe explicit data channels (e.g. network traffic) and read the content.

Suggested mitigations: Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

References: https://capec.mitre.org/data/definitions/117.html, http://cwe.mitre.org/data/definitions/319.html, https://cwe.mitre.org/data/definitions/299.html


### AC05 — Content Spoofing

- Target: **Persist disposable clones, worktrees, and job records**
- Severity: **Medium**
- Likelihood: Medium

An adversary modifies content to make it contain something other than what the original content producer intended while keeping the apparent source of the content unchanged. The term content spoofing is most often used to describe modification of web pages hosted by a target to display the adversary&#x27;s content instead of the owner&#x27;s content. However, any content can be spoofed, including the content of email messages, file transfers, or the content of other network communication protocols. Content can be modified at the source (e.g. modifying the source file for a web page) or in transit (e.g. intercepting and modifying a message between the sender and recipient). Usually, the adversary will attempt to hide the fact that the content has been modified, but in some cases, such as with web site defacement, this is not necessary. Content Spoofing can lead to malware exposure, financial fraud (if the content governs financial transactions), privacy violations, and other unwanted outcomes.

Suggested mitigations: Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

References: https://capec.mitre.org/data/definitions/148.html, http://cwe.mitre.org/data/definitions/345.html, https://cwe.mitre.org/data/definitions/299.html


### DE03 — Sniffing Attacks

- Target: **Persist disposable clones, worktrees, and job records**
- Severity: **Medium**
- Likelihood: 

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. The adversary may precipitate or indirectly influence the content of the observed transaction, but is never the intended recipient of the information. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient.

Suggested mitigations: Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

References: https://capec.mitre.org/data/definitions/157.html, http://cwe.mitre.org/data/definitions/311.html


### CR06 — Communication Channel Manipulation

- Target: **Persist disposable clones, worktrees, and job records**
- Severity: **High**
- Likelihood: Medium

An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.

Suggested mitigations: Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

References: https://capec.mitre.org/data/definitions/216.html


### CR08 — Client-Server Protocol Manipulation

- Target: **Persist disposable clones, worktrees, and job records**
- Severity: **Medium**
- Likelihood: Medium

An adversary takes advantage of weaknesses in the protocol by which a client and server are communicating to perform unexpected actions. Communication protocols are necessary to transfer messages between client and server applications. Moreover, different protocols may be used for different types of interactions. For example, an authentication protocol might be used to establish the identities of the server and client while a separate messaging protocol might be used to exchange data. If there is a weakness in a protocol used by the client and server, an attacker might take advantage of this to perform various types of attacks. For example, if the attacker is able to manipulate an authentication protocol, the attacker may be able spoof other clients or servers. If the attacker is able to manipulate a messaging protocol, the may be able to read sensitive information or modify message contents. This attack is often made easier by the fact that many clients and servers support multiple protocols to perform similar roles. For example, a server might support several different authentication protocols in order to support a wide range of clients, including legacy clients. Some of the older protocols may have vulnerabilities that allow an attacker to manipulate client-server interactions.

Suggested mitigations: Use strong authentication protocols.

References: https://capec.mitre.org/data/definitions/220.html, http://cwe.mitre.org/data/definitions/757.html


### DE01 — Interception

- Target: **Read clones and job context**
- Severity: **Medium**
- Likelihood: Medium

An adversary monitors data streams to or from the target for information gathering purposes. This attack may be undertaken to solely gather sensitive information or to support a further attack against the target. This attack pattern can involve sniffing network traffic as well as other types of data streams (e.g. radio). The adversary can attempt to initiate the establishment of a data stream, influence the nature of the data transmitted, or passively observe the communications as they unfold. In all variants of this attack, the adversary is not the intended recipient of the data stream. In contrast to other means of gathering information (e.g., targeting data leaks), the adversary must actively position himself so as to observe explicit data channels (e.g. network traffic) and read the content.

Suggested mitigations: Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

References: https://capec.mitre.org/data/definitions/117.html, http://cwe.mitre.org/data/definitions/319.html, https://cwe.mitre.org/data/definitions/299.html


### AC05 — Content Spoofing

- Target: **Read clones and job context**
- Severity: **Medium**
- Likelihood: Medium

An adversary modifies content to make it contain something other than what the original content producer intended while keeping the apparent source of the content unchanged. The term content spoofing is most often used to describe modification of web pages hosted by a target to display the adversary&#x27;s content instead of the owner&#x27;s content. However, any content can be spoofed, including the content of email messages, file transfers, or the content of other network communication protocols. Content can be modified at the source (e.g. modifying the source file for a web page) or in transit (e.g. intercepting and modifying a message between the sender and recipient). Usually, the adversary will attempt to hide the fact that the content has been modified, but in some cases, such as with web site defacement, this is not necessary. Content Spoofing can lead to malware exposure, financial fraud (if the content governs financial transactions), privacy violations, and other unwanted outcomes.

Suggested mitigations: Validation of user input for type, length, data-range, format, etc. Encoding any user input that will be output by the web application.

References: https://capec.mitre.org/data/definitions/148.html, http://cwe.mitre.org/data/definitions/345.html, https://cwe.mitre.org/data/definitions/299.html


### DE03 — Sniffing Attacks

- Target: **Read clones and job context**
- Severity: **Medium**
- Likelihood: 

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. The adversary may precipitate or indirectly influence the content of the observed transaction, but is never the intended recipient of the information. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient.

Suggested mitigations: Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

References: https://capec.mitre.org/data/definitions/157.html, http://cwe.mitre.org/data/definitions/311.html


### CR06 — Communication Channel Manipulation

- Target: **Read clones and job context**
- Severity: **High**
- Likelihood: Medium

An adversary manipulates a setting or parameter on communications channel in order to compromise its security. This can result in information exposure, insertion/removal of information from the communications stream, and/or potentially system compromise.

Suggested mitigations: Encrypt all sensitive communications using properly-configured cryptography.Design the communication system such that it associates proper authentication/authorization with each channel/message.

References: https://capec.mitre.org/data/definitions/216.html


### CR08 — Client-Server Protocol Manipulation

- Target: **Read clones and job context**
- Severity: **Medium**
- Likelihood: Medium

An adversary takes advantage of weaknesses in the protocol by which a client and server are communicating to perform unexpected actions. Communication protocols are necessary to transfer messages between client and server applications. Moreover, different protocols may be used for different types of interactions. For example, an authentication protocol might be used to establish the identities of the server and client while a separate messaging protocol might be used to exchange data. If there is a weakness in a protocol used by the client and server, an attacker might take advantage of this to perform various types of attacks. For example, if the attacker is able to manipulate an authentication protocol, the attacker may be able spoof other clients or servers. If the attacker is able to manipulate a messaging protocol, the may be able to read sensitive information or modify message contents. This attack is often made easier by the fact that many clients and servers support multiple protocols to perform similar roles. For example, a server might support several different authentication protocols in order to support a wide range of clients, including legacy clients. Some of the older protocols may have vulnerabilities that allow an attacker to manipulate client-server interactions.

Suggested mitigations: Use strong authentication protocols.

References: https://capec.mitre.org/data/definitions/220.html, http://cwe.mitre.org/data/definitions/757.html



