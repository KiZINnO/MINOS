
## The Project: Auto-Triage SOC Bot

**The Concept:** A Python CLI tool (or lightweight web API) that takes a raw security log—like a Sysmon event, a CrowdSec alert, or a raw Splunk export—automatically extracts the Indicators of Compromise (IoCs), queries them against Threat Intel APIs, and spits out a clean, formatted "Triage Report."

**Why it's perfect for vibe-coding:** LLMs are incredibly good at writing Regex (to extract IPs/hashes from messy logs) and handling JSON API responses. You will barely have to write any boilerplate code.

## The 5-Day Vibe-Coding Plan

Here is how you can break this down into a 5-day sprint:

1. **Day 1: The Extraction Engine.** Vibe-code a Python script that accepts a text file or raw log input. Have the AI write the regular expressions to accurately extract all IPv4 addresses, domains, and MD5/SHA256 hashes from the text.
    
2. **Day 2: Threat Intel Integration.** Register for free API keys from VirusTotal and AbuseIPDB. Prompt the AI to write asynchronous Python functions (`asyncio` and `aiohttp`) to query these APIs with your extracted IoCs without slowing down the script.
    
3. **Day 3: The Logic & Scoring.** Write the logic that determines the "Risk Score." For example, if AbuseIPDB returns a confidence score > 80%, flag the IP as "CRITICAL."
    
4. **Day 4: The Output Formatter.** Have the AI format the final output. It should generate a beautiful Markdown table or a clean JSON file that could theoretically be ingested back into a SIEM (like Splunk) or sent to a Discord webhook.
    
5. **Day 5: GitHub Polish.** Vibe-code an impressive `README.md`. Include a diagram of how it works, instructions on how to set up the `.env` file for the API keys, and sample log outputs.