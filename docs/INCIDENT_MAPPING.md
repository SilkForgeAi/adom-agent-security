# Incident mapping

The replay is derived from publicly reported stages of the OpenAI–Hugging Face incident while
remaining synthetic and non-exploitative.

| Publicly reported control failure | Synthetic fixture | ADOM boundary |
|---|---|---|
| Shared package cache used for communication | Cache message endpoint | Strict tool allowlist |
| Attempts to manipulate evaluation/scoring | Provenance-aware synthetic scorer | External receipt and scorer state |
| Unexpected Internet access | Declared sandbox loss plus direct target attempt | Network topology and egress boundary |
| Exposed credential discovery/use | Fake Hugging Face token | Credential and destination policy |
| Malicious dataset path | Synthetic upload step | Action policy and target isolation |
| File read, code execution, lateral movement | State-only synthetic target chain | Broker mediation and network segmentation |
| Repeated prohibited attempts | Retry sequence | Blast-radius failure circuit |

This mapping is a test design aid, not a reconstruction of undisclosed exploit details.

