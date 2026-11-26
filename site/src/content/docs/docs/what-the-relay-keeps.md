---
title: What the relay keeps
description: What a public WebVPN relay keeps of the traffic it carries, and for how long.
---

- **Where connections go:** not recorded. There is no log of the sites reached through the relay.
- **What it carries:** what the app encrypts, such as HTTPS, the relay cannot read. It sees which server and port each socket reaches and how much data passes.
- **Your IP address:** not stored, and it never leaves the relay. Before any usage is counted, it is turned into a code with a keyed hash (HMAC-SHA256) that includes the date, so the same address gives a different code each day.
- **Usage:** counted under a code that changes every day, in rows deleted after about 25 hours, so there is no lasting record per person.
- **Logs:** no request logs that identify anyone. The operational logs stay on FKN's own servers, are never sent to a third party and are deleted after 30 days. The health metrics are totals only, with no label per person or address, and are gone within two months.

This is what the public relays keep. They are run by Horion Corporation as part of FKN, and FKN's [privacy policy](https://fkn.app/privacy) covers them with the rest of FKN.
