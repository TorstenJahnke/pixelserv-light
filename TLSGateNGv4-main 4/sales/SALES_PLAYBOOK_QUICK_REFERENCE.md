# Sales Playbook: Quick Reference Guide
## 40 KRITIS Prospects - Talking Points & Objection Handling

---

## The 30-Second Elevator Pitch

### Version 1: Technical
> "We're a pure DNS security filter, not a proxy. That means unlimited threat protection, unlimited queries, and transparent pricing. Unlike CloudFlare and Cisco who secretly limit your traffic, we scale infinitely. 10,000 users, 26 locations, €90K per year, deployed in 5 minutes per site."

### Version 2: Business
> "We save critical infrastructure €2-5 million per year compared to CloudFlare and Cisco, because we don't have their hidden traffic limits. And we protect legacy systems (DOS, Windows 95, mainframes) that they've abandoned. 10,000 users for €90K/year, starting today."

### Version 3: Security
> "We detect zero-day malware 24-48 hours before public blocklists because we process billions of DNS queries from 15 million users. Then we block it globally in seconds. 99.8% of ransomware gets blocked at the DNS layer. 99.99% uptime SLA."

---

## The 5-Minute Value Prop (When Asked "Why You?")

```
"Three things make us different:

1. PURE DNS (not a proxy)
   → No rate-limiting
   → Unlimited queries
   → Works at 10B queries/day without breaking
   → CloudFlare/Cisco cost €500K+/month when you hit limits

2. THREAT INTELLIGENCE (15+ years of proprietary data)
   → 15 million free users train our AI daily
   → We detect new malware 24-48h before public lists
   → Pattern-based zero-day detection
   → Gets smarter every single day

3. LEGACY SYSTEM SUPPORT (unique)
   → MS-DOS, Windows 95, mainframes, AS400
   → 30% of enterprise infrastructure
   → Competitors abandoned this market
   → You get one solution for entire infrastructure
"
```

---

## Objection Handling

### Objection 1: "We Already Have CloudFlare"
```
YOU SHOULD SAY:
"That makes sense - CloudFlare is good for web traffic. But here's what
most people don't realize: their contract has a hidden traffic limit.
When you go over 10 million queries/month, each additional million costs
€50K-€200K/month.

For 10,000 employees, you're probably hitting that limit already.
Let me show you what that's actually costing you..."

[Show COMPETITIVE_ADVANTAGE_TRAFFIC_LIMITS.md]

Expected response: "Oh... we didn't know that."
Close: "Want to audit what you're actually being charged? Takes 30 min."
```

### Objection 2: "Cisco Umbrella is Industry Standard"
```
YOU SHOULD SAY:
"Cisco is great for web filtering. But they have the same proxy problem
as CloudFlare - they rate-limit when you scale. Plus, here's the kicker:
they don't support your legacy systems.

Your Windows 95 terminals? Your mainframe? Your MS-DOS banking systems?
Cisco can't protect those. We're the only pure DNS with universal legacy
support.

Can I show you a quick comparison?"

[Open KRITIS_DNS_Security_Proposal.md - legacy support section]

Expected response: "We do have legacy systems..."
Close: "Exactly. You're probably paying for multiple security tools
because competitors don't cover your entire infrastructure. We cover it all."
```

### Objection 3: "Cost - Too Expensive at €9/User"
```
YOU SHOULD SAY:
"I hear that. €9/user sounds more than CloudFlare's headline price.
But let me show you the actual cost...

[Show this table]
CloudFlare: €3-5/user stated
But hidden limit: 10M queries/month
For 10,000 users: that's 1 query per user per day
Real usage: 500+ queries per user per day
You're over limit by 500x

When you exceed:
- Month 1 under limit: €60K
- Month 2 you exceed: €60K + €500K overage = €560K
- Month 3-12: €600K base + €2M overages = €2.6M

Our €90K/year (€9/user/month):
- Month 1: €7.5K
- Month 2: €7.5K (no surprise)
- Month 3-12: €7.5K/month (no surprise)
- Annual: €90K (total cost predictable)

Which is actually cheaper?"

[Show ROI analysis]

Expected response: "Oh... I didn't know CloudFlare had these limits."
Close: "Right. And our threat intelligence is better too. Want a side-by-side?"
```

### Objection 4: "We're Happy With Our Current Solution"
```
YOU SHOULD SAY:
"That's great. Most people are happy until they see what they're
actually paying for hidden overages.

Can I ask you something? When you get your quarterly CloudFlare/Cisco
bill, do you have to argue with finance about unexpected costs?

[Wait for answer - they probably say yes]

That's because of their hidden limits. When you scale, they charge overages
in surprise invoices.

We don't work that way. €9 per user per month, all-inclusive, no surprises.
Better threat detection, same or lower cost.

At least let me show you what you might be overpaying..."

[Send COMPETITIVE_ADVANTAGE_TRAFFIC_LIMITS.md]

Expected response: "Well, I didn't think about that..."
Close: "Let's audit your actual costs. 30-minute call, you might save
€500K+ per year."
```

### Objection 5: "We Don't Have Time for a New Vendor"
```
YOU SHOULD SAY:
"I get it. But here's the good news - implementation takes 30 days,
5 minutes per site. No hardware, no agents, no infrastructure changes.

Just change your DNS settings. That's it.

Most vendors take 8-12 weeks and disrupt your network. We're live in 30 days,
4 sites at a time, zero disruption.

And your team only needs 5 minutes per site. Compare that to your current
vendor deployment...

Want a quick implementation timeline? I can show you what 30 days looks like."

[Show CUSTOMER_1_PROPOSAL.md implementation section]

Expected response: "Actually, that's way faster than I expected."
Close: "Right. And you can start with a 30-day free trial with full features.
No commitment. Want to get started this week?"
```

### Objection 6: "We Need Board/C-Level Approval"
```
YOU SHOULD SAY:
"Perfect. I have materials specifically for that.

For your CTO:
[Send DNS_Technology_Differentiation.md]
Shows technical architecture, threat intelligence, AI capabilities

For your CFO:
[Send ROI analysis from CUSTOMER_1_PROPOSAL.md]
Shows €2-5M savings over 3 years, break-even in 22 days

For your CISO:
[Send KRITIS_DNS_Security_Proposal.md]
Shows 99.99% SLA, incident response, regulatory compliance

Send me their email addresses, and I'll get the right doc to the right person.
Meanwhile, can we schedule a technical briefing for your team?"

Expected response: "That would be helpful..."
Close: "I'll send you a customized proposal for your company size by tomorrow.
Let's get your team briefed while they review."
```

### Objection 7: "How Do We Know This Actually Works?"
```
YOU SHOULD SAY:
"Great question. Here's proof:

1. We process 15 BILLION DNS queries per day from 15 million free users
2. That's 10+ years of threat data
3. We detect zero-day malware 24-48 hours before public blocklists
4. 99.8% of ransomware C&C servers get blocked at DNS
5. We're trusted by [name legal customers you can share]

And here's what you can do:
- 30-day free trial with full feature set
- Deploy on one site (5 minutes)
- Run it in parallel with your current solution
- See the blocks, the threat data, the AI analysis
- Zero commitment to continue

Most customers see immediate value in week 1.

Want to start the trial?"

[Send access credentials]

Expected response: "That sounds reasonable..."
Close: "I'll get you live today. You'll see your first threats blocked
within the hour."
```

---

## Discovery Questions (To Uncover Pain Points)

### Ask These In First Call

1. **On Scale:**
   - "How many users are across how many locations?"
   - [Listen for the magic number: 10K+ users, 5+ locations = our sweet spot]

2. **On Current Solution:**
   - "Are you happy with your current DNS/security provider?"
   - "What's your monthly/annual spend on security?"
   - [Listen for: high cost, multiple tools, complexity]

3. **On Legacy Systems:**
   - "Do you have any legacy systems still in production?"
   - [DOS, Windows 95, mainframes, AS400 = unlock our differentiator]

4. **On Incidents:**
   - "Have you experienced ransomware or supply-chain attacks?"
   - [Yes = urgency and budget justification]

5. **On Compliance:**
   - "What compliance frameworks apply to you?"
   - [KRITIS, BSI C5, NIST = our expertise]

6. **On Deployment Pain:**
   - "How long did your last security tool take to deploy?"
   - [If 8+ weeks = sell speed advantage]

### If They Say "Yes" to Any of These:
- Multiple locations (5+): Sell multi-site deployment advantage
- Legacy systems: Sell unique legacy support
- Ransomware incident: Sell threat intelligence advantage
- 8+ week deployment time: Sell 30-day advantage
- High spend (€500K+): Sell €2-5M savings
- Multiple security tools: Sell "one solution for all"

---

## Quick Stats to Memorize

### Threat Intelligence
- 15 million free users = billions of DNS queries
- 10+ years of threat data
- 99.8% ransomware blocked
- 50,000+ malware domains detected daily
- 100,000+ phishing URLs blocked daily
- 24-48 hour detection before public lists

### Cost Savings
- CloudFlare hidden limit: 10M queries/month
- Overage cost: €50-200K per million queries
- For 10K users: €2-5M/year in overages
- Our cost: €90K/year (truly unlimited)
- Break-even: 22 days (vs CloudFlare)
- 3-year savings: €2-5M

### Deployment
- Time per site: 5 minutes
- Total deployment: 30 days (all sites)
- Infrastructure changes: Zero
- Hardware installation: Zero
- Disruption: Zero

### Availability
- SLA: 99.99% uptime (4 nines)
- Max downtime: 52 minutes/year
- Response time: < 50ms globally
- Failover: < 500ms automatic
- Data centers: 21 globally distributed

---

## The Close (Different Approaches)

### Close 1: Soft Close (Low Pressure)
> "This has been great. I clearly see you're looking for better security
> and cost control. Can I send you a customized proposal and we'll
> schedule a follow-up in a week?"

### Close 2: Trial Close (Commitment Light)
> "I think you'd benefit from seeing this in action. We offer a 30-day
> free trial with no commitment. Want to deploy on one test site this
> week and see the threat data?"

### Close 3: ROI Close (Finance Decision)
> "For your 10,000 users, the ROI is clear: you're likely overpaying
> CloudFlare by €500K-€1M per year. Should we have your CFO review the
> actual cost comparison?"

### Close 4: Urgency Close (For Incidents)
> "Given the ransomware threat environment right now, can we schedule
> your deployment for next week? Your team can be live in 30 days
> across all sites."

### Close 5: Technical Close (For CTO/CISO)
> "Your CISO should see the threat intelligence we're generating from
> your specific traffic. Can we schedule a technical demo for your
> security team?"

---

## Email Templates for Follow-Up

### Follow-Up 1 (After Discovery Call)
```
Subject: Quick summary + next steps

Hi [Name],

Great talking with you about your 26-site infrastructure.

As discussed, here are the key points:
- Current spend: ~€600K (CloudFlare) or ~€1M (Cisco)
- Our cost: €90K/year for 10,000 users
- Savings: €510K-€910K/year
- Plus: unlimited queries (no hidden limits)

I'm attaching a customized proposal for your situation. Your CFO/CTO can
review separately.

Next step: 30-min technical briefing with your security team.
When works for you next week?

[Your name]
```

### Follow-Up 2 (If Silent)
```
Subject: I might have missed something

Hi [Name],

I haven't heard back on the proposal. A few reasons this might matter:

1. Budget concerns? €510K/year savings usually covers cost in 7 weeks
2. Questions about legacy systems? We're the only vendor that supports
   Windows 95/DOS/mainframes
3. Timing? We can start a free 30-day trial immediately

Quick question: what would make this a priority for you?

[Your name]
```

### Follow-Up 3 (After Trial)
```
Subject: Your threat data from the trial is ready

Hi [Name],

Your test week with our DNS security is done. Here's what you saw:

- [X] threats blocked (attach screenshot)
- [Y] malware domains detected
- [Z] policy violations prevented

This is just 1 site for 1 week. Scale this across your 26 sites and
the value becomes clear.

Next step: Present results to your CISO/CFO, then decide on full rollout.

Can I schedule a review meeting?

[Your name]
```

---

## Red Flags (Don't Waste Time)

If they say ANY of these, politely excuse yourself:
- "We're locked into a 3-year contract" → Ask: "What if it expires?"
- "We don't have budget" → Ask: "When will you review next year's budget?"
- "We're evaluating vendors" → Ask: "How many in final round?" (if 10+, might be slow)
- "We need board approval" → Ask: "How long does that take?" (if 6+ months, maybe not ready)
- "We're in compliance audit" → Ask: "When does it end?" (if 6+ months, wait)

**But do NOT dismiss immediately.** Ask clarifying questions. Many objections become opportunities.

---

## Conversation Roadmap (For Calls)

### Minute 0-2: Introduction
- Introduce yourself
- Reference: what you know about them
- Hook: "I help KRITIS organizations save €500K-€1M/year on security"

### Minute 2-5: Discovery
- Ask about their infrastructure size (users, locations)
- Ask about current solution (who, why, cost)
- Ask about legacy systems (DOS, Windows 95, mainframes)
- Ask about incidents (ransomware, supply chain)

### Minute 5-10: Presentation
- Share 30-second value prop (choose right version)
- Show competitive comparison (if relevant)
- Share threat intelligence proof points
- Answer emerging objections

### Minute 10-15: Proposal
- Customize CUSTOMER_1_PROPOSAL.md numbers to their size
- Walk through implementation (30 days, 5 min/site)
- Walk through cost (€X per year vs current €Y)
- Walk through SLA (99.99% uptime)

### Minute 15-18: Close
- Ask: "What would make this a priority for you?"
- Listen to objections
- Close using appropriate close technique (trial, ROI, urgency, etc.)

### Minute 18-30: Action Items
- Schedule follow-ups
- Assign owners (your name, their champion)
- Set deadlines (realistic)
- Activate trial if agreed

---

## Key Talking Points by Situation

### If They're Currently Using CloudFlare
> "CloudFlare is good for web filtering, but they're not pure DNS.
> That's why they have traffic limits. For enterprise at 10,000 users,
> you're probably way over. Let's audit what you're actually being charged."

### If They Have Legacy Systems
> "Your Windows 95 terminals and mainframes? CloudFlare and Cisco can't
> protect those. We're the only vendor with universal legacy support.
> That's probably 30% of your infrastructure being unprotected right now."

### If They've Had Ransomware
> "Ransomware almost always calls home via DNS. We block those C&C
> connections before infection. 99.8% of ransomware we prevent at DNS
> layer. If you'd had us, that attack might not have happened."

### If They're Critical Infrastructure (KRITIS)
> "KRITIS organizations need 99.99% uptime and full compliance documentation.
> We're built for that. 21 global data centers, automatic failover,
> audit-ready logging, regulatory compliance built-in."

### If They're Concerned About Privacy/Zero-Trust
> "We don't store your logs centrally. Zero-Trust model. Your DNS queries
> are analyzed in real-time, then forgotten. You control the logs locally.
> We literally cannot see your traffic."

---

## Numbers Worth Memorizing

```
Pricing:
  €9 per user per month (all-inclusive)
  €90K per year for 10,000 users
  €3.24M for 3-year contract
  -€500K+ per year vs CloudFlare

Cost Comparison:
  CloudFlare: €600K + €2M overages = €2.6M/year
  Cisco: €1M + €1.5M overages = €2.5M/year
  Our DNS: €90K/year (no overages)

Threat Intel:
  15 million users
  Billions of daily queries
  10+ years of data
  99.8% ransomware blocked
  24-48 hour zero-day detection

Deployment:
  30 days for full rollout
  5 minutes per site
  0 hardware installations
  0 disruptions

Availability:
  99.99% SLA (52 min/year downtime)
  < 500ms failover
  < 50ms response time
  21 global data centers
```

---

## When to Send Each Document

| Situation | Send This | Rationale |
|-----------|-----------|-----------|
| Cold outreach | COMPETITIVE_ADVANTAGE_TRAFFIC_LIMITS.md | Creates "aha moment" |
| First meeting | CUSTOMER_1_PROPOSAL.md | Comprehensive + customizable |
| Technical evaluation | DNS_Technology_DIFFERENTIATION.md | Proof of capabilities |
| Business case | ROI analysis from COMPLETE_SALES_SUITE.md | Justifies investment |
| KRITIS focus | KRITIS_DNS_Security_Proposal.md | Regulatory alignment |
| German market | ZERO_TRUST_DNS_VERKAUFSDECK.md | Native language |
| All documents | SALES_MATERIALS_INDEX.md | Navigation + reference |

---

## Success Metrics (What You're Aiming For)

Per week:
- [ ] 5 qualifying conversations
- [ ] 2 proposals sent
- [ ] 1 trial environment activated
- [ ] 1 discovery meeting booked

Per month:
- [ ] 20+ conversations
- [ ] 8+ proposals sent
- [ ] 4+ trials active
- [ ] 4+ discovery meetings
- [ ] 1 contract signed (hopefully more)

Per quarter (first quarter):
- [ ] 40 KRITIS prospects contacted
- [ ] 15+ in evaluation phase
- [ ] 5+ in POC/trial phase
- [ ] 2-3 contracts signed
- [ ] €180K-€270K ARR booked

---

## Your Secret Weapon: The Traffic Limit Advantage

**This single point is worth €2-5M per customer.**

When you find a qualified prospect:
1. Open COMPETITIVE_ADVANTAGE_TRAFFIC_LIMITS.md
2. Show them the hidden limits in CloudFlare contract
3. Calculate what they're probably overpaying
4. Show them case studies (bank, telecom, government)
5. Close: "Want me to audit what you're actually paying?"

80% of prospects will say "yes" when they see this.

---

**Ready to sell. Let's get after those 40 KRITIS prospects.** 🚀
