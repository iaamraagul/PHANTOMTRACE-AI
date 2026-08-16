# Dataset provenance

Primary: UCI ML Repository, PhiUSIIL Phishing URL (Website), dataset 967, donated 2024, 235,795 rows and 54 features. Official source: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset. License: CC BY 4.0. `FILENAME` is ignored; label `1` means legitimate and `0` means phishing.

Benchmark: UCI ML Repository, Phishing Websites, dataset 327, 11,055 rows and 30 integer features. Official source: https://archive.ics.uci.edu/dataset/327/phishing. License: CC BY 4.0. It is evaluated independently, never concatenated with PhiUSIIL because feature semantics differ.

Current intelligence:

- PhishTank developer/API information: https://www.phishtank.net/developer_info.php and https://www.phishtank.net/api_info.php
- URLhaus project/API information: https://urlhaus.abuse.ch/ and https://urlhaus.abuse.ch/api/

Live-source labels are not used as supervised-training labels without a provenance review. PhishTank and URLhaus are optional enrichment providers behind explicit environment configuration.
