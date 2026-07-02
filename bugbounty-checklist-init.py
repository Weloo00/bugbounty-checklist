#!/usr/bin/env python3
"""
Bug bounty hunting checklist generator.

Run it, type a target/project name, pick which vulnerability categories
you actually want, and it builds a folder with one markdown checklist per
chosen category. Each item has a plain-English explanation of what to
test, how to test it, and a list of creative, real-world-report-grounded
attack scenarios (sourced from actual disclosed bug bounty writeups,
deduplicated and merged by technique) - plus a spot right below for your
own notes. Safe to re-run on the same folder later - it will never
overwrite a file that already exists, so your notes are never lost.

Usage:
    python3 bugbounty-checklist-init.py                    interactive: pick a target name, categories, and format
    python3 bugbounty-checklist-init.py -n target -a       all 17 categories, no prompts (defaults to .md)
    python3 bugbounty-checklist-init.py -n target -c 2,4,5,7,11
    python3 bugbounty-checklist-init.py -n target -c 1-6 -f txt
    python3 bugbounty-checklist-init.py -l                 list categories (with item counts) and exit
"""

import argparse
import os
import random
import re
import sys
import datetime

# ---------------------------------------------------------------------------
# Checklist content. Each category is (folder_name, display_title, body_md).
# ---------------------------------------------------------------------------

CATEGORIES = [
("01-Recon", "Recon & Asset Discovery", """# Recon & Asset Discovery

Goal of this phase: find as much real attack surface as possible before
you start attacking anything. Time spent here almost always pays off later.

## [ ] 1. Enumerate subdomains and live hosts

**What it is:** finding every subdomain that belongs to the target, then
checking which ones are actually alive and responding.

**How to test:**
- Passive: subfinder, assetfinder, crt.sh, Chaos dataset
- Active: puredns/massdns to resolve, httpx to probe which ones are live
- Compare against the program's scope list before touching anything

**Creative angles:**
- Look for forgotten dev/staging/UAT subdomains that were never added to
  the WAF rules or auth requirements the production site has.
- Check for subdomains tied to acquired companies/products - they often
  run on completely different, less-hardened infrastructure.
- Try permutation tools (dnsgen, gotator) on subdomains you've already
  found - "api-v2" often exists next to "api", "old-" next to nothing.

**My notes:**


---

## [ ] 2. Fingerprint the technology stack

**What it is:** figuring out what frameworks, CMS, server software, and
third-party services power the target.

**How to test:**
- Check response headers (Server, X-Powered-By)
- Look at cookies (JSESSIONID, PHPSESSID, etc. hint at the stack)
- Use Wappalyzer / httpx -tech-detect
- Check error pages for stack traces (they often name the framework)

**Looks interesting when:** you find an outdated version with known CVEs,
or a stack that suggests custom code sitting on top of a known package
(that seam between "vendor code" and "custom code" is often where the
real bugs live - vendor code is usually well-tested, the glue code
around it usually isn't).

**My notes:**


---

## [ ] 3. Download and analyze JS files for secrets/endpoints

**What it is:** client-side JS often contains API endpoints, hidden
parameters, or hardcoded secrets that never show up by clicking around.

**How to test:**
- Pull every unique .js file the site loads
- Grep for: api key patterns (AIza, sk_live_, AKIA...), `/api/`, `fetch(`,
  `axios.`, hardcoded internal URLs, TODO/FIXME comments
- Watch for the file being generic framework code vs actually custom
  (custom code is where the real bugs live)

**Looks interesting when:** you find endpoints not linked anywhere in the
UI, or literal credentials/tokens.

**My notes:**


---

## [ ] 4. Check robots.txt and sitemap.xml

**What it is:** these files are meant to guide search engines, but they
often accidentally reveal paths the owner wanted hidden from search but
forgot are still fully public.

**How to test:**
- GET /robots.txt and /sitemap.xml (and nested sitemaps they reference)
- Try every Disallow'd path directly - "hidden from Google" does not mean
  "requires authentication"

**Looks interesting when:** a Disallow entry points to something that
sounds administrative, legacy, or sensitive.

**My notes:**


---

## [ ] 5. Search for API docs / GraphQL introspection

**What it is:** many APIs expose their own documentation or schema if you
know where to look, effectively handing you the whole attack surface map.

**How to test:**
- Try /api/docs, /swagger.json, /openapi.json, /graphql (POST introspection
  query), /api-docs, /v1/docs
- If GraphQL, send the standard `__schema { types { name fields { name } } }`
  introspection query

**Looks interesting when:** introspection is enabled in production, or the
docs reveal endpoints/fields you hadn't found by crawling.

**My notes:**


---

## [ ] 6. Check historical/archived URLs

**What it is:** old endpoints that were removed from the current site but
never actually decommissioned server-side.

**How to test:**
- gau / waybackurls against the target
- Filter for interesting patterns: admin, api, debug, internal, .json, .bak

**Looks interesting when:** an old endpoint still returns 200 and does
something, especially if it predates the current auth/captcha model.

**My notes:**


---

## [ ] 7. Search for leaked secrets tied to the target

**What it is:** developers accidentally commit API keys, internal URLs, or
credentials to public repos.

**How to test:**
- GitHub/GitLab code search for the target's domain name, internal
  hostnames, or distinctive internal class/variable names you've found
- trufflehog against any repos you find

**Looks interesting when:** you find a real, still-valid credential or an
internal hostname/IP not otherwise discoverable.

**My notes:**


---

## [ ] 8. Confirm exact in-scope vs out-of-scope boundaries

**What it is:** re-reading the program's scope page carefully before you
go further, since this determines what's even worth testing.

**How to test:**
- List every in-scope target and its tier/payout range
- List every explicit exclusion (vuln classes, specific sub-features)
- Note anything ambiguous so you can frame reports around it later

**My notes:**


---
"""),

("02-Authentication", "Authentication", """# Authentication

Everything to do with proving who you are: login, registration,
password reset, MFA, email/username changes. This is consistently the
highest-density area for real, payable bugs, and it rewards creativity -
the checks here are rarely wrong in an obvious way, they're wrong in a
specific, narrow way that only shows up if you think like the developer
who built the flow and then deliberately break their assumption.

## [ ] 1. Password reset and/or recovery

**What it is:** the flow a user goes through when they forget their
password. Extremely bug-dense because it's often built separately from
the main login flow, sometimes more than once (legacy + modern versions
living side by side).

**How to test:**
- Map every path that can trigger a reset (main flow, any legacy/alternate
  URLs, mobile app deep links, admin-initiated resets)
- Check: is there a CAPTCHA, and is it actually verified server-side (send
  empty vs garbage token, compare error messages)?
- Check: is there rate limiting? Send several requests back to back.
- Check: does the response differ for a real account vs a fake one
  (message text, response time)?
- Check: is the reset token predictable, long enough, single-use, and
  does it expire? Does requesting a new token invalidate the old one?

**Real-world creative scenarios (grounded in actual disclosed reports):**
1. **Weak token generation** - a researcher found a program's password
   reset function generated tokens with insufficient entropy, making them
   guessable (MTN Group, disclosed on HackerOne).
2. **Reset link not actually invalidated after use** - reuse the same
   "used" reset link a second time and see if it still works.
3. **Host header injection in the reset email** - if the reset link is
   built using the Host header instead of a hardcoded domain, sending a
   different Host can get a victim's reset link generated pointing at
   an attacker-controlled domain (only report if you can show the token
   actually leaking to your server this way).
4. **Self-XSS via the reset form itself** - a disclosed Shopify report
   found stored/reflected XSS injectable through the password reset
   flow's own input fields.
5. **Missing rate limit lets you spam a victim's inbox** - multiple
   disclosed reports (Nextcloud, HackerOne itself, Weblate) were exactly
   this: no throttle on the reset-request endpoint, letting an attacker
   flood any known email with reset messages.
6. **Legacy endpoint bypasses a CAPTCHA the modern flow enforces** - check
   for an old-style servlet/VF/classic page doing the same job as the
   current UI flow but without the newer protections.
7. **Response manipulation** - some apps decide client-side whether the
   reset "succeeded" based on a JSON field in the response; intercept and
   flip `"success": false` to `true` and see if the client lets you
   proceed anyway.
8. **Combine with email-change** - a New Relic report chained "change the
   account's email" with "trigger a password reset" to fully take over an
   account without ever knowing the original password.
9. **Injection in the reset lookup query itself** - the "enter your email"
   field runs a database lookup that's sometimes forgotten when the team
   hardens the main login form; test it for SQL injection the same as any
   other input (see the Injection checklist for payloads).

**My notes:**


---

## [ ] 2. Login rate limiting / brute force protection

**What it is:** whether the login form actually stops repeated wrong-password
attempts against the same account.

**How to test:**
- Send 20-30 wrong-password attempts against one test account, spaced
  out slightly (this is explicitly allowed on most programs under the
  "auth flow" carve-out even when general rate limiting is excluded)
- Check for: delay increase, lockout, CAPTCHA escalation
- If a lockout kicks in, test bypasses: trailing whitespace in the
  username, case changes, alternate email casing

**Creative angles:**
- Try rotating a header like `X-Forwarded-For` between attempts if the
  lockout appears to be purely IP-based rather than account-based.
- Try the mobile app's login API separately from the web login - they're
  often built by different teams with different (usually weaker) limits.
- If there's a lockout after N attempts, check whether a *successful*
  login resets the counter, and whether that can be abused to keep
  probing indefinitely by interleaving one correct low-value login.

**My notes:**


---

## [ ] 3. Username / email enumeration

**What it is:** figuring out whether an attacker can tell if a given
email/username has an account, without knowing the password.

**How to test:**
- Compare responses for: valid username + wrong password, vs a username
  you're sure doesn't exist
- Compare on: exact wording, response size, response time
- Test this on login, registration, and password reset separately -
  each one can leak differently, and it's common for a team to fix
  enumeration on login but forget to fix it identically on registration
  or reset.

**Creative angles:**
- Timing side-channel even when the message content is identical: a
  request against a real account that has to do real work (generate a
  token, queue an email) is often measurably slower than one against a
  nonexistent account that short-circuits early. Test with a single cold
  request per candidate, not a burst - repeated hits to the same target
  can trigger a "recently requested" fast-path that hides the signal.
- Check the "resend verification email" or "resend invite" functions -
  these are frequently unprotected copies of the same enumeration bug.

**My notes:**


---

## [ ] 4. CAPTCHA - presence check vs real verification

**What it is:** many apps add a CAPTCHA field but never actually verify
it server-side against the provider (Google/hCaptcha/etc).

**How to test:**
- Send the request with the captcha field empty - note the exact error
- Send it again with a random garbage string instead - if you get a
  *different* error message, the token is genuinely being checked. If
  you get the *same* "empty" error, it's not checking content, just
  presence - if it succeeds outright, it's not being checked at all.

**Creative angles:**
- Check whether a captcha solved for one action (e.g. "contact us") can
  be replayed against a more sensitive action (login/register) if the
  server only checks "is this a valid token from the provider" without
  checking which site-key/action it was issued for.
- Check whether removing the field key entirely behaves differently from
  sending it as an empty string - inconsistent handling sometimes reveals
  a code path that skips validation.
- A disclosed report against Instagram-brand infrastructure found a
  captcha bypass on the single most important gated function on the
  page - always test the captcha on the *specific* action that matters
  most, not just a generic contact form.

**My notes:**


---

## [ ] 5. Password policy strength

**What it is:** whether the app actually enforces a minimum password
standard.

**How to test:**
- Try registering/changing password to: "a", "123456", the same as the
  username, a password used before (reuse check)

**My notes:**


---

## [ ] 6. 2FA / MFA

**What it is:** whether the second factor can be skipped, brute-forced,
or bypassed by manipulating the flow.

**How to test:**
- Check if the OTP/code is rate limited (a 6-digit code is only ~1M
  combinations - trivial to brute force without a limit)
- Check if you can skip straight to the post-MFA page by guessing/
  replaying the URL, or by stopping the flow right after step 1 (password
  accepted) and directly calling whatever endpoint step 2 normally calls
- Check if the "remember this device" cookie/token can be forged, replayed
  on a different account, or never actually expires

**Real-world creative scenarios:**
1. **2FA bypass via response manipulation** - a disclosed HackerOne
   report found the business logic simply trusted a client-side flag
   after step 1; intercepting and editing the response (or the next
   request) skipped the second factor entirely. Also seen against a
   large enterprise target's login page.
2. **Non-functional 2FA recovery codes** - a disclosed Legal Robot
   report found the backup/recovery codes for 2FA simply didn't work as
   a bypass path, which is worth testing in both directions: do they
   work when they should, and can they be reused when they shouldn't?
3. **OTP verification skippable during signup** - a disclosed Tucows
   VDP report found a business logic error let an attacker complete
   registration while entirely bypassing the OTP verification step.
4. **Claiming/verifying via OTP manipulation** - a disclosed report
   against a food delivery platform found OTP manipulation let an
   attacker claim a business listing that wasn't theirs.
5. **Backup code accepted without ever being validated server-side** - a
   disclosed report found the "use a backup code" path accepted any
   correctly-formatted random value, because the server never actually
   compared it against the user's real stored codes.
6. **OTP rate limit keyed off a spoofable header** - a disclosed report
   found the verification endpoint's throttle used `X-Forwarded-For`
   instead of the session, so rotating that header on each attempt gave
   unlimited OTP brute-force tries.
7. **2FA skipped entirely on an alternate account flow** - a disclosed
   Instagram-adjacent report found that reactivating a deactivated
   account required only the password, no 2FA prompt, unlike normal login.
8. **Stale 2FA session survives a password change or 2FA removal** - a
   disclosed report showed that reaching the 2FA input page, then
   changing the password or disabling 2FA as the victim, still let the
   attacker "try another way" and complete the original login.
9. **2FA sidestepped entirely via the password-reset path** - the reset
   flow hands over the account without ever touching the OTP, making the
   whole second factor moot; a disclosed Microsoft/Outlook report used
   exactly this chain at scale.

**My notes:**


---

## [ ] 7. Account lockout and its bypass

**What it is:** confirming lockout exists, then trying to get around it.

**How to test:**
- Trigger a lockout, then try: different IP (if testing allows), username
  case variation, adding a trailing dot/space to the email

**My notes:**


---

## [ ] 8. Legacy or alternate authentication endpoints

**What it is:** older auth mechanisms (classic servlet-style login/reset
pages, mobile-only APIs, SSO fallback paths) that were never fully
decommissioned when the app moved to a newer framework.

**How to test:**
- Check robots.txt for hints (Disallow rules sometimes point straight
  at the legacy path)
- Try common legacy paths for the platform you're on (e.g. for
  Salesforce Experience Cloud: /secur/forgotpassword.jsp, /SiteLogin,
  /CommunitiesSelfReg; for generic stacks: /login.jsp,
  /j_security_check, /wp-login.php next to a custom SSO)
- Compare their behavior (captcha, rate limit, token strength) against
  the modern flow doing the same job

**Looks vulnerable when:** a legacy path still works and has weaker
protection than its modern equivalent - this is a very reliable bug
class once you find it, because it proves the team already built the
right control, just not everywhere it needed to be.

**My notes:**


---

## [ ] 9. Registration / signup abuse

**What it is:** the account-creation flow, tested for the same class of
issues as login, plus its own unique ones (mass assignment, response
trust, domain-based auto-trust).

**How to test:**
- Add extra fields to the registration payload that the UI never sends:
  role, isActive, isAdmin, accountType, verified, tier
- Test whether email verification is actually required before the
  account gets real privileges, or only cosmetically shown as "pending"
- Test registering with a Unicode homograph of a trusted domain
  (Cyrillic а instead of Latin a) to see if any domain-based auto-trust
  logic uses naive string matching

**Real-world creative scenarios:**
1. **Account creation without auth via response manipulation** - a
   disclosed DoD report found that intercepting and editing the server's
   response to a failed/incomplete registration request could still
   result in a created, usable account.
2. **Registration linking to someone else's existing record** - many
   platforms try to match a new signup to an existing customer/contact
   record by email; if the match/link step trusts a client-supplied
   record ID instead of re-deriving it server-side, a new signup can get
   linked to (and see) someone else's existing data.
3. **Weak/no rate limit on signup enables mass fake-account creation**,
   useful context if combined with any per-account bonus/referral system.

**My notes:**


---

## [ ] 10. Email or username change flow

**What it is:** letting a logged-in user change the email/username tied
to their account - a surprisingly common source of full account takeover.

**How to test:**
- Change your email, then check: does a confirmation go to the *old*
  email too (so the real owner gets warned), or only the new one?
- Check if the change takes effect immediately or only after confirming
  the new address - if immediate, an attacker who can trigger this on
  someone else's session (via CSRF, XSS, etc.) doesn't need the
  confirmation step at all.
- Check whether the "current password" is required to change the email -
  if not, a hijacked/idle session can be fully taken over silently.

**Real-world creative scenarios:**
1. **Logic issue in email change process** - two separate disclosed
   Legal Robot reports found flaws specifically in how the email-change
   confirmation logic was implemented.
2. **Weak email-change functionality leading to account takeover** - a
   disclosed Weblate report is a direct example of this exact chain.
3. **"Change password" logic inversion** - one of the more unusual
   disclosed bugs: the password-change endpoint's success/failure logic
   was literally inverted under a specific condition, worth testing by
   deliberately sending malformed/edge-case input to any change-password
   or change-email form and watching for backwards behavior, not just
   errors.

**My notes:**


---

## [ ] 11. "Remember me" / persistent login abuse

**What it is:** long-lived tokens meant to keep a user logged in across
sessions - if predictable, non-expiring, or not tied to the right scope,
they become a long-term backdoor into an account.

**How to test:**
- Check the token's format/length for predictability
- Log out normally - does the "remember me" token still work afterward?
- Check whether the token is bound to anything (IP, user agent) or
  works from anywhere once captured
- A disclosed report noted abuse of "Remember Me" functionality as its
  own distinct finding - worth testing in isolation, not just as an
  afterthought of session management.

**My notes:**


---

## [ ] 12. Response manipulation / client-side trust

**What it is:** the broadest and most creative category here - any point
where the client-side app decides what to do next based on a value the
server sent, rather than the server enforcing it. If you can intercept
and edit the *response* (not just the request), you may be able to walk
straight past a check the UI thinks it made you pass.

**How to test:**
- After any auth-adjacent action (login, 2FA, payment confirmation,
  admin check), look at the raw response JSON for booleans/status fields
  like `success`, `authorized`, `role`, `verified` - then intercept and
  flip them before the client-side JS processes them
- Check whether the next request in the sequence is gated only by what
  the previous response said, or whether the server re-validates
  independently

**Real-world creative scenarios:**
1. **Admin panel login bypass via response manipulation** - a disclosed
   Sony report found exactly this: editing the login response let the
   client proceed as if authenticated to an admin panel.
2. **2FA bypass via response manipulation on a login page** - seen
   against a large enterprise target; the second factor was enforced
   entirely client-side.
3. **Manipulating a response to get free access to a paid feature** - a
   disclosed Logitech/Streamlabs report found that editing an
   entitlement-check response granted premium access without paying.

**My notes:**


---

## [ ] 13. OAuth token/code theft via redirect manipulation

**What it is:** an OAuth flow leaks the access token or auth code to an
attacker-controlled destination by abusing an open redirect, a weak
`redirect_uri` check, or a Referer-based post-login redirect - handing
over the victim's session without a password.

**How to test:**
- Map the full OAuth flow and note every redirect (login CSRF entry
  point, callback, final landing).
- Change `response_type` from `code` to `code,token` so tokens land in
  the URL fragment.
- Try to steer the callback to your domain via `redirect_uri`, a
  parser-quirk open redirect, or a spoofed Referer header, then read
  the token/fragment on your listener.

**Source:** a disclosed Airbnb report used exactly this chain.

**My notes:**


---

## [ ] 14. SSO bypass via subdomain takeover + shared cookies

**What it is:** SSO systems that scope session cookies to the parent
domain trust every subdomain; if any subdomain has a dangling DNS
record, an attacker claims it and harvests or relays the shared session
cookies to take over accounts. See the Subdomain Takeover checklist for
the claiming step itself.

**How to test:**
- Enumerate subdomains and look for dangling CNAMEs pointing to
  unregistered cloud hosts.
- Check whether session/CSRF cookies are scoped to the parent domain.
- Claim the dangling host, serve JS that triggers the login flow, and
  test whether shared cookies persist and can be replayed in a fresh
  browser.

**Source:** two separate disclosed Uber-related reports used this exact
technique against different SSO implementations.

**My notes:**


---

## [ ] 15. SAML assertion / audience validation bypass

**What it is:** a SAML Service Provider fails to properly validate the
assertion's Audience, signature, expiry, or subject, so an assertion
minted for a different provider (or a tampered one) is accepted and
logs the attacker in as any user.

**How to test:**
- Capture a valid SAML assertion (even from a different SP you control).
- Replay it to the target's ACS endpoint after editing the
  AudienceRestriction, subject, or timestamps.
- Watch for signature-wrapping tricks, stripped signatures, and
  expired-but-accepted assertions.

**Source:** a disclosed Slack SAML authentication bypass report.

**My notes:**


---

## [ ] 16. Client-side-only auth control bypass (DOM/inspect element)

**What it is:** a restriction such as an account lockout or a disabled
button is enforced only in the frontend while the backend accepts the
request, so removing the disabled state or replaying the request in
DevTools performs the blocked action.

**How to test:**
- Trigger the locked/disabled state (session timeout, rate lock,
  greyed-out control).
- Remove the disabled attribute/class via DevTools, or replay the
  underlying request directly in Burp.
- If the server processes it without re-auth, the control is
  client-side only.

**Source:** a disclosed Stripe-related report ("inspect element leads to
account lockout bypass") used exactly this.

**My notes:**


---

## [ ] 17. Local/biometric auth bypass via runtime instrumentation (mobile)

**What it is:** mobile apps that gate access on a local biometric
boolean without server-side verification can be bypassed by hooking the
callback at runtime and flipping the result to "success."

**How to test:**
- On a jailbroken/rooted device, attach Frida/Objection to the app.
- Hook the biometric evaluation callback and trigger the prompt with a
  wrong fingerprint.
- Confirm access is granted, proving the check is local-only with no
  runtime-integrity protection.

**Source:** a disclosed report found this against both Evernote and
Dropbox's iOS Touch ID implementations.

**My notes:**


---

## Further reading - real disclosed reports referenced above

- https://hackerone.com/reports/765031 - Weak passwords generated by password reset function (MTN Group)
- https://hackerone.com/reports/1691195 - Missing rate limiting on password reset lets you spam emails (Nextcloud)
- https://hackerone.com/reports/12782 - Spamming any user from reset password function (HackerOne)
- https://hackerone.com/reports/1089467 - Account takeover via email change + forgot password combo (New Relic)
- https://hackerone.com/reports/2571981 - Business logic error bypasses 2FA requirement (HackerOne)
- https://hackerone.com/reports/249337 - Non-functional 2FA recovery codes (Legal Robot)
- https://hackerone.com/reports/3255473 - OTP verification bypass during signup (Tucows)
- https://hackerone.com/reports/1330529 - Claiming a listing via OTP manipulation (Eternal)
- https://hackerone.com/reports/2061982 - Account creation without auth via response manipulation (U.S. Dept of Defense)
- https://hackerone.com/reports/266017 / 265931 - Logic issue in email change process (Legal Robot)
- https://hackerone.com/reports/223461 - Weak email change functionality leads to account takeover (Weblate)
- https://hackerone.com/reports/255679 - Change password logic inversion (Legal Robot)
- https://hackerone.com/reports/37822 - Abuse of "Remember Me" functionality (X/xAI)
- https://hackerone.com/reports/1508661 - Response manipulation leads to admin panel login bypass (Sony)
- https://hackerone.com/reports/2962527 - 2FA bypass via response manipulation on login page (U.S. Dept of Defense)
- https://hackerone.com/reports/1070510 - Manipulating response leads to free access to a paid product (Logitech)
- https://hackerone.com/reports/206653 - Captcha bypass for the most important function (Automattic)
- https://www.arneswinnen.net/2017/06/authentication-bypass-on-airbnb-via-oauth-tokens-theft/ - OAuth token theft via redirect
- https://www.arneswinnen.net/2017/06/authentication-bypass-on-ubers-sso-via-subdomain-takeover/ - SSO bypass via subdomain takeover
- https://blog.intothesymmetry.com/2017/10/slack-saml-authentication-bypass.html - SAML assertion bypass
- https://www.jonbottarini.com/2017/04/03/inspect-element-leads-to-stripe-account-lockout-authentication-bypass/ - client-side-only lockout bypass
- https://medium.com/@pig.wig45/touch-id-authentication-bypass-on-evernote-and-dropbox-ios-apps-7985219767b2 - biometric bypass via Frida
- https://medium.com/@ultranoob/weird-and-simple-2fa-bypass-without-any-test-b869e09ac261 - backup code not validated
- https://medium.com/@YumiSec/how-to-bypass-a-2fa-with-a-http-header-ce82f7927893 - OTP rate limit bypass via header
- https://bugbountypoc.com/instagram-account-is-reactivated-without-entering-2fa/ - 2FA skipped on reactivation
- https://medium.com/@lukeberner/how-i-abused-2fa-to-maintain-persistence-after-a-password-change-google-microsoft-instagram-7e3f455b71a1 - stale 2FA session
- https://goyalvartul.medium.com/how-i-hacked-40-000-user-accounts-of-microsoft-using-2fa-bypass-outlook-live-com-13258785ec2f - 2FA sidestepped via reset
"""),

("03-Session-Management", "Session Management", """# Session Management

## [ ] 1. Session fixation

**What it is:** whether the session ID stays the same before and after
login, letting an attacker pre-set a victim's session token.

**How to test:**
- Note your session token before logging in
- Log in
- Check if the token changed. It should.

**My notes:**


---

## [ ] 2. Session invalidation on logout

**What it is:** whether a session token still works after you've logged out.

**How to test:**
- Log in, capture the session cookie/token
- Log out
- Replay a request using the old token - it should be rejected

**Creative angle:** a disclosed report described exactly this as a
"browser cache management and logout vulnerability" - test not just the
session token itself, but whether cached authenticated pages/data remain
viewable via back-button or browser cache after logout on a shared
machine.

**My notes:**


---

## [ ] 3. Session token predictability

**What it is:** whether session tokens are generated with enough
randomness that you can't guess someone else's.

**How to test:**
- Grab several tokens in a row (e.g. multiple logins) and look for
  any visible pattern, sequential structure, or short length

**My notes:**


---

## [ ] 4. Concurrent session handling

**What it is:** what happens when the same account is logged in from two
places at once.

**How to test:**
- Log in from two different browsers/devices
- Change the password from one - does the other session get killed?

**My notes:**


---

## [ ] 5. Cookie security flags

**What it is:** whether session cookies are protected from basic theft
vectors.

**How to test:**
- Check for HttpOnly (blocks JS access), Secure (HTTPS only), and
  SameSite (CSRF protection) flags on every session-related cookie

**My notes:**


---

## [ ] 6. Session token leakage

**What it is:** whether the session token ever ends up somewhere it
shouldn't - URLs, Referer headers, logs, third-party analytics.

**How to test:**
- Check if the token is ever passed as a URL parameter (leaks via
  browser history, Referer header to third parties, server logs)

**My notes:**


---
"""),

("04-Authorization-Access-Control", "Authorization & Access Control", """# Authorization & Access Control

This category tends to produce the most consistently payable bugs.

## [ ] 1. IDOR (Insecure Direct Object Reference)

**What it is:** the app trusts an ID you send it (record ID, user ID,
order ID) instead of checking that the ID actually belongs to you.

**How to test:**
- Create two test accounts, A and B
- Find any request that includes an ID belonging to your own data
- While logged in as A, replay the request with B's ID instead
- If you get B's data back, it's IDOR

**Creative angles:**
- Don't stop at swapping the numeric ID - also try replacing it with an
  email, username, or UUID if the app accepts multiple identifier
  formats for the same object.
- Try case changes on the parameter name itself (`userId` vs `userid` vs
  `UserID`) - some frameworks apply the access-control check only to one
  casing and the data layer accepts all of them.
- Test both "blind" IDOR (you can't see the result directly, but a side
  effect proves it worked - an email gets sent, a counter changes) and
  "generic" IDOR (the response hands the data straight back).
- Look specifically at file/attachment download endpoints with
  incrementing numeric IDs - a disclosed report found IDOR letting one
  user claim another user's uploaded ID documents as their own.
- Test bulk/list endpoints, not just single-record ones - a disclosed
  Uber-adjacent report found a UUID enumeration issue on a
  bulk-activation endpoint that let ranges of other users' identifiers
  be probed at once.

**My notes:**


---

## [ ] 2. Horizontal privilege escalation

**What it is:** accessing another user's data/actions at the *same*
privilege level as you (this overlaps heavily with IDOR but can also
apply to actions, not just data reads).

**How to test:**
- Same two-account technique as IDOR, but focused on state-changing
  actions (edit, delete, submit-on-behalf-of) rather than just reads

**Real-world creative scenarios:**
1. **Deleting someone else's content via a "report" feature** - a
   disclosed Vanilla Forums report found that the "report as abuse"
   function could be abused to delete any user's post, since the
   deletion logic trusted the reporter's target ID without re-checking
   who actually owned the moderation action.
2. **Editing someone else's comments/posts via a social feature** - a
   disclosed Rockstar Games Social Club report found comment
   insertion/deletion tied to a user ID parameter that wasn't verified
   against the session.
3. **Parameter manipulation exposing other users' orders/subscriptions**
   - two separate disclosed Starbucks reports found this exact pattern
   on order viewing and on editing another user's subscription shipping
   address.

**My notes:**


---

## [ ] 3. Vertical privilege escalation

**What it is:** a low-privilege user reaching functionality meant for a
higher-privilege role (user -> admin).

**How to test:**
- As a normal user, try directly requesting admin-only URLs/API calls
- Check if role/permission checks happen only in the UI (hidden button)
  vs actually enforced server-side
- Check whether switching the HTTP method changes the outcome - a
  disclosed Frontegg report found that PATCH requests could escalate a
  user's own API key permissions in a way that GET/POST correctly
  blocked; the access-control middleware simply hadn't been applied to
  every method.

**My notes:**


---

## [ ] 4. Forced browsing

**What it is:** reaching pages/functionality that aren't linked anywhere,
but still exist and respond.

**How to test:**
- Directory/endpoint bruteforce (ffuf) once authenticated as a low-priv
  user, looking for admin/internal-sounding paths

**My notes:**


---

## [ ] 5. Mass assignment

**What it is:** an API/form accepts more fields than it should, letting
you set values you were never meant to control (isAdmin, role, status).

**How to test:**
- Take a legitimate request (e.g. registration or profile update) and
  add extra fields the UI never sends: isActive, role, isAdmin, status,
  ownerId, profileId - one at a time so you know which one (if any)
  actually gets applied

**My notes:**


---

## [ ] 6. JWT tampering

**What it is:** if the app uses JWTs, checking whether the signature is
actually verified and whether the algorithm can be downgraded.

**How to test:**
- Try changing `alg` to `none` and stripping the signature
- Try re-signing with a guessed/weak secret (if HS256)
- Try swapping the `kid` header to point at a file/key you control

**My notes:**


---

## [ ] 7. Read IDOR on nested/sub-objects

**What it is:** access control is applied to the top-level object (a
dashboard) but not to the child objects it contains (individual charts),
so swapping a child ID - often in a GraphQL variable - discloses another
user's private data.

**How to test:**
- Find IDs of sub-resources (chart, widget, attachment, comment) inside
  a parent you own.
- Replace the ID with another user's/admin's in the API or GraphQL
  mutation/query.
- Check the response for leaked data even when the parent is marked
  private.

**Source:** a disclosed Facebook Analytics report used exactly this
pattern to leak private dashboard chart data.

**My notes:**


---

## [ ] 8. Write/add IDOR - assigning unauthorized users

**What it is:** a create/update request accepts an arbitrary user ID for
a role (co-host, member, collaborator) without checking the relationship
or permission, letting you add non-friends or blocked users.

**How to test:**
- Perform the action legitimately (add a friend as co-host) and
  intercept the request.
- Swap the member/co-host ID parameter for an unrelated or blocked
  user's ID.
- Forward and confirm the unauthorized user is attached server-side.

**Source:** a disclosed Facebook report showed adding blocked/non-friend
users as event co-hosts this way.

**My notes:**


---

## [ ] 9. Delete/action IDOR - operating on others' objects

**What it is:** a state-changing action (delete, edit) only checks that
the target ID exists, not that the caller owns it, so substituting a
victim's object ID performs the action on their resource.

**How to test:**
- Trigger the action on your own object and capture the request.
- Replace the object ID with a victim's.
- Resubmit and verify the victim's object was deleted/modified.

**Source:** a disclosed report demonstrated deleting any user's video
poll this way.

**My notes:**


---

## [ ] 10. Function/role-level access (low-priv role sees restricted data)

**What it is:** a limited role (e.g., a Page "analyst") can reach
admin-only data or endpoints because authorization checks the login, not
the specific permission level for that resource.

**How to test:**
- Create/obtain a low-privilege role on a shared asset.
- Directly call the higher-privilege endpoints (job applications,
  insights, settings) that role shouldn't see.
- Compare against what the UI exposes; a data leak confirms missing
  function-level checks.

**Source:** a disclosed report found a Page analyst role could view job
application details meant for admins only.

**My notes:**


---

## Further reading - real disclosed reports referenced above

- https://hackerone.com/reports/411075 - Report-as-abuse function abused to delete any user's post (Vanilla)
- https://hackerone.com/reports/141090 - Parameter manipulation exposes other users' orders (Starbucks)
- https://hackerone.com/reports/141120 - Parameter manipulation edits another user's subscription (Starbucks)
- https://hackerone.com/reports/2149124 - PATCH method escalates API key permissions (Frontegg)
- https://bugreader.com/jubabaghdad@disclose-private-dashboard-charts-name-and-data-in-facebook-analytics-184 - nested-object IDOR
- https://bugreader.com/binit@adding-anyone-including-non-friend-and-blocked-people-as-co-host-in-personal-event-181 - write IDOR
- https://bugreader.com/testgrounds@deleting-anyones-video-poll-175 - delete IDOR
- https://bugreader.com/rony@page-analyst-could-view-job-application-details-213 - function-level access IDOR
"""),

("05-Cross-Site-Scripting", "Cross-Site Scripting (XSS)", """# Cross-Site Scripting (XSS)

XSS is its own dedicated category here because it's the single largest,
most technique-diverse vuln class in bug bounty history - the real skill
isn't knowing "inject a script tag," it's knowing the ~20 different
contexts and carriers a payload can travel through.

## [ ] 1. Reflected XSS via URL parameter

**What it is:** a value from the query string (or path) is echoed back
into the HTML response without encoding, so a crafted parameter runs
script in the victim's browser.

**How to test:**
- Inject a unique marker (e.g. `xss1234`) into every parameter and find
  where it reflects in the response.
- Break out of the context you land in: `"><svg onload=alert(1)>` for
  HTML body, `"onmouseover=alert(1)` inside a tag attribute.
- Watch for parameter-specific behavior - one param may be filtered
  while a sibling isn't, so test them all individually.
- Try adding non-standard parameters (some apps reflect arbitrary
  `?debug=`/`?utm_` values that were never intended to be tested).

**My notes:**


---

## [ ] 2. Stored XSS via user-content fields

**What it is:** input saved by the app (profile name, comment, review,
support ticket, filename) is later rendered to other users unescaped, so
the payload fires for everyone who views it.

**How to test:**
- Seed every persisted field (username, bio, address, comment, uploaded
  filename, alt-text) with a payload and view it back on all pages that
  render it.
- Check the *display* context, not the edit form - a field safe in an
  input box may be raw in a listing, email, or admin view.
- Try fields that echo into less obvious places: image `alt` text,
  markdown editors, open-graph embeds, macro/template fields.

**My notes:**


---

## [ ] 3. DOM-based XSS via a client-side sink

**What it is:** JavaScript reads attacker-controlled data (`location.hash`,
`location.search`, `postMessage`, `document.referrer`) and writes it into
a dangerous sink (`innerHTML`, `document.write`, `eval`) with no server
involvement.

**How to test:**
- Grep the site's JS for sources (`location.*`, `document.URL`,
  `referrer`, `postMessage`) flowing into sinks (`innerHTML`,
  `document.write`, `.html()`, `eval`, `setTimeout`).
- Put payloads after `#` so they never hit the server:
  `#"><img src=x onerror=alert(1)>`.
- For rich-text/editor sinks, use malformed tags to slip past client
  filters.

**My notes:**


---

## [ ] 4. Client-side template injection (AngularJS / framework `{{ }}`)

**What it is:** input lands inside an AngularJS (or similar) template
region, so instead of plain HTML the framework evaluates your `{{ }}`
expression - which can be escaped into full JS execution.

**How to test:**
- Inject `{{7*7}}` and look for `49` in the output to confirm the
  template engine evaluates your input.
- Confirm the page loads Angular (`ng-app`) and that your reflection
  sits inside the Angular-bound DOM.
- Escalate with a sandbox-escape payload for the Angular version in use
  to reach `alert(document.domain)`.

**My notes:**


---

## [ ] 5. Escalating Self-XSS into a real XSS

**What it is:** an XSS that only fires in your own account/session
becomes exploitable against others by forcing the payload into the
victim's session or view.

**How to test:**
- Use login/logout CSRF to log the victim into *your* account so your
  stored self-XSS fires in their browser, then pivot.
- Try cookie tossing / cookie-injection to plant the malicious value in
  the victim's session.
- Chain with CSRF on the field-saving request so the payload is written
  to the victim's own profile.
- Combine with clickjacking/UI redressing to trick the victim into
  submitting the self-XSS themselves.

**My notes:**


---

## [ ] 6. WAF / input-filter bypass

**What it is:** the injection point is reachable but a WAF or blacklist
strips obvious payloads; the fix is to smuggle the same payload in a
form the filter doesn't recognize.

**How to test:**
- Swap tags/handlers the filter misses (`<svg>`, `<details open
  ontoggle=>`, `<img src onerror=>`) and mix case if it only blocks
  lowercase.
- Use encodings: HTML entities, URL/double-URL, unicode, and JS
  `String.fromCharCode` to rebuild the payload.
- Break keywords with junk the parser ignores (`java\\tscript:`) and test
  on a 403/blocked response - the block page itself may reflect input.

**My notes:**


---

## [ ] 7. Blind XSS in admin / support panels

**What it is:** a stored payload fires later in a place you can't see -
a staff dashboard, CRM, ticket viewer, or log console - reached by
"poisoning the well" with data an internal user will open.

**How to test:**
- Drop `<script src=//yourcollector></script>` payloads into fields
  staff read: name, address, user-agent, support tickets, feedback forms.
- Use a callback collector (XSS Hunter style) that alerts you and
  captures DOM/cookies/URL wherever it executes.
- Prioritize inputs that flow into multiple back-office systems.

**My notes:**


---

## [ ] 8. XSS via file upload (SVG / HTML)

**What it is:** the app lets you upload a file that the browser renders
as markup - an SVG (which can hold `<script>`) or an HTML file - served
from an in-scope origin.

**How to test:**
- Upload an SVG containing `<script>alert(document.domain)</script>`
  and open it directly; SVGs execute script when viewed as a document.
- If extension/MIME is checked, try `.svg` with `image/svg+xml`, or
  smuggle HTML with a fake image content-type and see if it's served
  inline.
- Check where the file is served - same-origin execution matters; a
  separate sandbox domain kills impact.

**My notes:**


---

## [ ] 9. Polymorphic / content-type image XSS

**What it is:** a file that is a valid image *and* valid HTML/JS - the
server accepts it as an image but the browser can be coaxed into
executing embedded script.

**How to test:**
- Embed a payload in image data that survives re-processing (JPEG ECS
  segment, PNG IDAT chunk).
- Request the uploaded image with an `.html` extension or where the CDN
  serves it as `text/html` without `nosniff`.
- Confirm it's served same-origin so execution has useful context.

**My notes:**


---

## [ ] 10. MIME-sniffing XSS (missing `nosniff`)

**What it is:** a response with a non-HTML or missing `Content-Type`
still executes because the browser sniffs the bytes and renders it -
enabled by a missing `X-Content-Type-Options: nosniff`.

**How to test:**
- Find endpoints that reflect input but return `text/plain`,
  `application/json`, etc., and check whether `nosniff` is absent.
- Send an HTML/script payload and open the raw response directly in a
  browser.
- Also test responses where you control the `Content-Type` (wrong
  header set by the app).

**My notes:**


---

## [ ] 11. XSSI / JSONP data theft

**What it is:** a JS or JSONP endpoint returns sensitive data as an
executable script; a malicious page includes it with `<script>` (or
supplies a callback) and reads the data cross-origin.

**How to test:**
- Hunt endpoints returning JavaScript/JSONP with user data (look for
  `callback=` params or responses starting with variable assignments).
- Include the endpoint via `<script src=...>` on your page and override
  globals/prototype setters to capture the leaked values.
- For JSONP, supply your own `callback=attackerFn` to receive the data
  directly.

**My notes:**


---

## [ ] 12. XSS via WebSocket messages

**What it is:** data received over a WebSocket is written into the
page's HTML unescaped; if the socket also lacks Origin checks, an
attacker page can drive it (cross-site WebSocket hijacking) app-wide.

**How to test:**
- Find the `ws://`/`wss://` URL in the site's JS and inspect how
  incoming messages are rendered (look for `innerHTML` on message data).
- Send a message that breaks HTML context, respecting any required
  framing the client expects.
- Test whether the socket accepts connections from a foreign Origin.

**My notes:**


---

## [ ] 13. Reflected XSS escalated via HTTP request smuggling

**What it is:** a reflected XSS that needs no user interaction is
delivered to *other* users by smuggling a request through a
front-end/back-end desync so the poisoned response is served to the
next visitor.

**How to test:**
- First confirm a normal reflected XSS, then test the front-end for
  CL.TE/TE.CL desync.
- Smuggle a request whose reflected response lands on another user's
  connection.

**My notes:**


---

## [ ] 14. DOM clobbering / mutation XSS

**What it is:** in sanitized/no-JS contexts (like AMP email), injecting
elements with crafted `id`/`name` attributes overwrites JavaScript
variables or DOM references, steering trusted code into an unsafe state.

**How to test:**
- Where you can inject HTML but not `<script>`, add elements like `<a
  id=target>` to clobber globals the page's JS relies on.
- Combine with browser HTML-parser quirks (mXSS): payloads that mutate
  into script after the sanitizer runs.
- Focus on sanitized rich contexts - email HTML, markdown renderers,
  AMP.

**My notes:**


---

## [ ] 15. XSS in email / webmail rendering

**What it is:** HTML email (or AMP-for-email) is rendered by a webmail
client that under-sanitizes, so a crafted message executes script in
the mail app's origin.

**How to test:**
- Send yourself HTML mail with payloads in body, subject, sender name,
  and attachment names; open in the web/mobile client.
- Probe allowed-but-dangerous constructs (CSS, SVG, AMP components,
  conditional comments) the mail sanitizer overlooks.
- Test both desktop-web and mobile-app renderers separately.

**My notes:**


---

## [ ] 16. CSP bypass to fire a blocked XSS

**What it is:** you have injection but Content-Security-Policy blocks
execution; you bypass it by abusing a whitelisted host, a JSONP endpoint
on an allowed domain, or a reusable nonce/`unsafe-eval` gap.

**How to test:**
- Read the CSP and look for weak allowlist entries (a domain hosting a
  callable JSONP/AngularJS file).
- Load script from the allowed origin to satisfy the policy while
  running your code.
- Check for `unsafe-eval`, reused static nonces, or missing
  `object-src`/`base-uri`.

**My notes:**


---

## [ ] 17. Web cache poisoning → stored XSS

**What it is:** an unkeyed input (a custom or non-standard header) is
reflected unsanitized and the response is cached, so one poisoned
request serves XSS to every subsequent visitor of that URL.

**How to test:**
- Detect caching (`X-Cache`, `Age`, CDN headers) on a page that reflects
  input.
- Use Param Miner to brute-force unkeyed headers and find one that
  reflects.
- Inject the XSS via that header on a cacheable URL, confirm the
  poisoned response is returned to a clean client.

**My notes:**


---

## [ ] 18. Cookie-based XSS

**What it is:** the app reflects a cookie value into the page unescaped;
since cookies can be set via a subdomain, a param, or another bug, the
attacker controls the cookie and thus the XSS.

**How to test:**
- Find where cookie values echo into HTML/JS, then set that cookie to a
  payload.
- Note that `HttpOnly` doesn't help here - the server writes the raw
  value into the response.
- Chain with any cookie-setting primitive to make it deliverable to a
  victim.

**My notes:**


---

## [ ] 19. HTTP parameter pollution → XSS

**What it is:** supplying a parameter twice makes the server concatenate
or pick values differently than the validation layer expects, letting a
payload slip past a whitelist into a sink.

**How to test:**
- Duplicate the target parameter (`?dest=allowed.com&dest=alert(1)`) and
  observe how the app joins them.
- Use it to bypass URL/redirect whitelists that only validate one
  instance.
- Try both query-string and body params, mixed-case/encoded key
  variants.

**My notes:**


---

## [ ] 20. XSS from non-standard input sources (Referer / header / path)

**What it is:** input that isn't an obvious form field - `Referer`,
`User-Agent`, `Host`, or path segments - gets reflected into the page.

**How to test:**
- Fuzz headers (`Referer`, `User-Agent`, `X-Forwarded-For`, `Host`) with
  a marker and check for reflection.
- Test path-based and error/404 pages that echo the requested URL.
- Deliver via a controlled page (auto-setting Referer) or a request that
  forces the header for the victim.

**My notes:**


---

## [ ] 21. XSS → account takeover / session hijack

**What it is:** proving real impact by using the XSS to steal session
material (cookies, localStorage/JWT), CSRF tokens, or to perform
authenticated actions - turning a low-severity alert into a real account
takeover.

**How to test:**
- Exfiltrate `document.cookie` (if not HttpOnly) or read
  `localStorage`/`sessionStorage` tokens and send to your collector.
- If cookies are HttpOnly, script an authenticated request from within
  the page (read the CSRF token, change email/password).
- Demonstrate the full chain end-to-end rather than just a proof alert.

**My notes:**


---

## [ ] 22. XSS → RCE (Electron / desktop clients)

**What it is:** in a desktop app built on a web view (Electron) with
Node integration, an XSS gains access to `require`/`child_process` and
executes OS commands.

**How to test:**
- Identify desktop/Electron apps that render remote or synced content
  in a web view.
- If `nodeIntegration` is on, run
  `require('child_process').exec(...)` from the XSS context.
- Even without Node, probe custom protocol handlers and privileged
  bridges the app exposes.

**My notes:**


---

## [ ] 23. SSRF / CORS chained into XSS

**What it is:** a server-side fetch (SSRF) or a permissive CORS policy
lets the app pull attacker-controlled content into a trusted origin,
where it's rendered or reflected as script.

**How to test:**
- For SSRF: point the server at a URL you control returning HTML/JS and
  check whether the response is rendered back in a page.
- For CORS: find endpoints with credentialed origin reflection, then
  inject into a trusting page.

**My notes:**


---

## [ ] 24. XSS via legacy Flash / SWF files

**What it is:** legacy Flash SWFs accept `FlashVars` that flow into
`ExternalInterface.call`, allowing `javascript:` execution. Mostly
historical (Flash EOL), only relevant on old assets still serving SWFs.

**How to test:**
- Find hosted `.swf` helpers and pass payloads via known vulnerable
  params.
- Test DOM-based SWF params that reach `ExternalInterface`.

**My notes:**


---

## Further reading - real disclosed reports referenced above

- http://www.noob.ninja/2017/09/story-of-parameter-specific-xss.html - parameter-specific reflected XSS
- https://buer.haus/2014/06/16/facebook-stored-cross-site-scripting-xss-badges/ - stored XSS
- https://labs.detectify.com/2017/07/27/how-we-invented-the-tesla-dom-doom-xss/ - DOM XSS
- https://medium.com/@impratikdabhi/reflected-xss-on-microsoft-com-via-angular-template-injection-2e26d80a7fd8 - Angular template injection
- https://whitton.io/articles/uber-turning-self-xss-into-good-xss/ - self-XSS escalation
- https://infosecwriteups.com/unicode-vs-waf-xss-waf-bypass-128cd9972a30 - WAF bypass
- https://thehackerblog.com/poisoning-the-well-compromising-godaddy-customer-support-with-blind-xss/index.html - blind XSS
- https://guptashubham.com/svg-xss-in-unifi-v5-0-2/ - SVG upload XSS
- https://blog.doyensec.com/2020/04/30/polymorphic-images-for-xss.html - polymorphic image XSS
- https://www.komodosec.com/post/mime-sniffing-xss - MIME sniffing XSS
- https://medium.com/bugbountywriteup/effortlessly-finding-cross-site-script-inclusion-xssi-jsonp-for-bug-bounty-38ae0b9e5c8a - XSSI/JSONP
- https://medium.com/@osamaavvan/exploiting-websocket-application-wide-xss-csrf-66e9e2ac8dfa - WebSocket XSS
- https://hazana.xyz/posts/escalating-reflected-xss-with-http-smuggling/ - XSS + smuggling
- https://research.securitum.com/xss-in-amp4email-dom-clobbering/ - DOM clobbering
- https://www.bishopfox.com/blog/2017/06/how-i-built-an-xss-worm-on-atmail/ - webmail XSS
- https://medium.com/@tbmnull/making-an-xss-triggered-by-csp-bypass-on-twitter-561f107be3e5 - CSP bypass
- https://nahoragg.medium.com/chaining-cache-poisoning-to-stored-xss-b910076bda4f - cache poisoning to XSS
- https://medium.com/@momenbasel/from-parameter-pollution-to-xss-d095e13be060 - parameter pollution
- https://medium.com/a-bugz-life/from-reflected-xss-to-account-takeover-showing-xss-impact-9bc6dd35d4e6 - XSS to ATO
- https://ysx.me.uk/taking-note-xss-to-rce-in-the-simplenote-electron-client/ - XSS to RCE (Electron)
- https://ad3sh.medium.com/how-i-found-xss-via-ssrf-vulnerability-adesh-kolte-873b30a6b89f - SSRF to XSS
"""),

("06-Injection", "Injection (SQLi, LFI, SSTI, XXE, Command, NoSQLi, Buffer Overflow)", """# Injection

## [ ] 1. SQLi - basic parameter injection (quote -> error -> ORDER BY / UNION)

**What it is:** the classic entry point - a URL or form parameter is
placed into a SQL query unsanitized, so a stray quote breaks the query
and lets you extend it.

**How to test:**
- Append a single quote `'` to numeric/string params and watch for a
  500 error or changed response.
- Confirm with `' ORDER BY 1--`, incrementing until it errors, to count
  columns.
- Extend to `UNION SELECT` to pull data (version, current DB, table
  contents).

**My notes:**


---

## [ ] 2. SQLi - login/auth bypass via injection

**What it is:** injecting into a login form's username or password so
the WHERE clause always evaluates true, logging you in without valid
credentials.

**How to test:**
- Try `' OR 1=1-- -`, `admin'-- -`, `' OR '1'='1` in username and
  password fields.
- Watch for a successful login or a different redirect vs. a normal
  failed attempt.
- If it lands you in as the first DB row, try `' OR 1=1 LIMIT 1-- -` to
  control which account.

**My notes:**


---

## [ ] 3. SQLi - blind boolean / time-based extraction

**What it is:** no data or errors are echoed back, so you ask the DB
true/false questions and read the answer from a content difference or a
deliberate delay.

**How to test:**
- Boolean: compare responses of `' AND 1=1-- -` vs `' AND 1=2-- -`.
- Time-based: `' AND SLEEP(5)-- -` (MySQL) or `'; WAITFOR DELAY
  '0:0:5'-- -` (MSSQL) and measure response time.
- Extract char-by-char with `SUBSTRING()`/`IF()`; speed up with a `CASE
  ... WHEN` that maps many candidate values in one request.

**My notes:**


---

## [ ] 4. SQLi via User-Agent (and other headers)

**What it is:** apps that log or query request headers can be injectable
through the User-Agent, Referer, or Cookie - places scanners often skip.

**How to test:**
- Put a `'` in the User-Agent header and watch for an error or a
  status-code change.
- Confirm boolean-style: `' AND 1=1` (normal) vs `' AND 1=2` (error).
- Fingerprint the DB with version-probe functions, then extract.

**My notes:**


---

## [ ] 5. SQLi via Host / X-Forwarded-Host header

**What it is:** backends (often behind load balancers/CDNs) that look
up the host value in a DB can be injected through the Host or
X-Forwarded-Host header.

**How to test:**
- Note CDN/LB fingerprints, then inject SQL into `X-Forwarded-Host`.
- Confirm with a time delay and check the response time.
- If symbols are filtered, use sqlmap with a tamper script to dump.

**My notes:**


---

## [ ] 6. SQLi - WAF bypass to reach injection

**What it is:** a WAF sits in front of an otherwise-injectable param;
you defeat it with obfuscation, encoding, tamper scripts, or by abusing
its inconsistent/random blocking.

**How to test:**
- Swap blocked functions for equivalents (`SUBSTRING`->`LIKE`,
  `IF`->`CASE WHEN`), try inline comments/case-swapping.
- Use sqlmap `--tamper` scripts (between, space2comment, charencode).
- If the WAF blocks randomly, script automatic retries until a real DB
  response comes through.

**My notes:**


---

## [ ] 7. SQLi in INSERT/UPDATE queries (and comma-restricted contexts)

**What it is:** write-path queries (registration, profile update,
feedback) are injectable too, and sometimes the app splits input on
commas so you must avoid them.

**How to test:**
- Inject into fields that get stored and look for delayed/second-order
  effects when the value is later read.
- Break out of the VALUES/SET clause and append a sub-select.
- If commas are stripped, use `CASE WHEN (subquery LIKE 'a%') THEN
  sleep(1) ELSE 2 END` with `LIKE` instead of `SUBSTRING()`.

**My notes:**


---

## [ ] 8. SQLi in the forgot/reset-password function

**What it is:** the "enter your email to reset" flow runs a lookup
query on your input and is frequently forgotten by devs - a soft target
for injection.

**How to test:**
- Submit `email'` and watch for an error vs. the normal "no such email"
  message.
- Confirm quote parsing with `email''` (should behave normally again).
- Fingerprint backend from the stack and go time-based, then automate
  with sqlmap.

**My notes:**


---

## [ ] 9. Blind SQLi via file upload (filename/metadata)

**What it is:** if an uploaded file's name or metadata is stored in the
DB unsanitized, the filename itself becomes the injection carrier.

**How to test:**
- Upload a file, then in Burp replace the filename with a payload while
  keeping a valid extension.
- Use a time-based payload and step the delay to prove execution.
- Remember a front WAF may need bypassing before the delay shows.

**My notes:**


---

## [ ] 10. SQLi to file read / write -> RCE (LOAD_FILE / INTO OUTFILE)

**What it is:** with FILE privileges on MySQL, injection escalates
beyond data theft - read local files or drop a webshell into the
webroot.

**How to test:**
- Read: `UNION SELECT LOAD_FILE('/etc/passwd')`.
- Write a shell: `UNION SELECT '<?php system($_GET[c]); ?>' INTO
  OUTFILE '/var/www/html/s.php'`.
- Needs a known writable webroot path and `secure_file_priv` off.

**My notes:**


---

## [ ] 11. DBMS-specific injection (Oracle, BigQuery, Postgres)

**What it is:** not every backend is MySQL - Oracle, BigQuery, and
Postgres have their own syntax, and filtered characters can force
creative operators.

**How to test:**
- Fingerprint: Oracle accepts `rownum` and `||` string concat; Postgres
  uses `||` and stacked queries; BigQuery uses standard-SQL functions.
- On Oracle with filtered special characters, chain via `||`
  concatenation and use `LIKE` for char matching.

**My notes:**


---

## [ ] 12. SQLi hidden behind a redirect / gated page

**What it is:** a page returns 200 then immediately redirects to login;
stopping the redirect exposes the real page and its injectable
parameters.

**How to test:**
- Use a "no-redirect" browser extension or Burp to intercept and drop
  the 302 to view the underlying page.
- Enumerate parameter endpoints on that page.
- Test `'` (500) then `' ORDER BY 1-- -` (200) to confirm, then dump
  with sqlmap while still blocking the redirect.

**My notes:**


---

## [ ] 13. Server-Side Template Injection (SSTI)

**What it is:** user input gets evaluated as a template expression.

**How to test:**
- Send `{{7*7}}`, `${7*7}`, `<%= 7*7 %>` into inputs
- If you see `49` come back instead of the literal text, you likely
  have SSTI - escalate carefully from there (see the RCE checklist for
  the full escalation paths per language/framework)

**My notes:**


---

## [ ] 14. XXE (XML External Entity)

**What it is:** an XML parser that resolves external entities, letting
you read local files or make outbound requests.

**How to test:**
- Find anywhere the app accepts XML (including inside file uploads like
  SVG/DOCX) and send a payload with a DOCTYPE defining an external
  entity pointing at a local file or your own listener

**Creative angle:** a disclosed Semrush report found XXE specifically
inside a "Site Audit" feature that parsed uploaded/crawled content -
look for any feature that parses a document format server-side, not
just an obvious "upload XML" button.

**My notes:**


---

## [ ] 15. Command Injection

**What it is:** user input reaching a shell command.

**How to test:**
- Inject `; whoami`, `| whoami`, `` `whoami` `` into inputs that might
  touch system commands (file conversion, ping/network tools, export
  features)
- Blind version: use `; sleep 5` and watch timing

**My notes:**


---

## [ ] 16. Path Traversal - basics in include / download params

**What it is:** a parameter that names a file (`?page=`, `?file=`,
`?download=`) is passed to the filesystem without sanitizing `../`,
letting you climb out and read arbitrary files.

**How to test:**
- Try `?page=../../../../etc/passwd` and `....//....//` variants for
  stripped-traversal filters.
- Add null-byte/extension tricks on older stacks.
- On Windows targets swap to `..\\\\..\\\\..\\\\windows\\\\win.ini`.

**My notes:**


---

## [ ] 17. LFI -> RCE via log poisoning

**What it is:** you inject PHP into a value the server logs (User-Agent,
Referer), then include that log file through the LFI so the PHP
executes.

**How to test:**
- Use `phpinfo()` or traversal to locate the access/error log path.
- Send a request with PHP in the Referer/User-Agent:
  `<?php system($_GET['c']); ?>`.
- Include the log via LFI and append `?c=id` to run commands.

**My notes:**


---

## [ ] 18. LFI -> RCE via PHP sessions and wrappers

**What it is:** beyond logs, LFI can execute code by including PHP
session files you control, or by abusing PHP wrappers like
`php://filter` (source disclosure) and `data://`/`expect://`.

**How to test:**
- Read source with
  `php://filter/convert.base64-encode/resource=index.php`.
- Poison your session: put PHP into a value stored in `$_SESSION`, then
  include the session file by path.
- Where allowed, try `data://text/plain;base64,<payload>` or
  `expect://id`.

**My notes:**


---

## [ ] 19. LFI + file upload chained to RCE

**What it is:** LFI alone can't run your code unless you can also place
a payload on disk - combine it with a (possibly restricted) upload
feature to get a shell.

**How to test:**
- Use LFI recon first to learn what runs on the box so you upload a
  compatible payload.
- Bypass the upload's extension check (tamper the extension/content-type).
- Include the uploaded file via the LFI path to trigger execution.

**My notes:**


---

## [ ] 20. NoSQL Injection

**What it is:** the NoSQL equivalent of SQLi, common on MongoDB-backed
apps.

**How to test:**
- Try sending an object instead of a string where JSON is accepted,
  e.g. `{"username": {"$ne": null}, "password": {"$ne": null}}` on login

**My notes:**


---

## [ ] 21. Buffer overflow - stack-based, overwriting the return address

**What it is:** writing more data into a fixed-size stack buffer than it
holds spills into adjacent memory, including the saved return address,
letting an attacker redirect execution when the function returns.
Relevant if the target ships a native binary/agent, not just a web app.

**How to test:**
- Feed growing inputs to a local binary/field and watch for a crash.
- Confirm you reached the saved return pointer by seeing your bytes in
  the instruction pointer at crash time.
- Root cause is unbounded copies (`strcpy`, `gets`, `sprintf`) with no
  length check.

**My notes:**


---

## [ ] 22. Buffer overflow - finding the offset and controlling EIP

**What it is:** the practical exploitation flow - locate the exact
offset that overwrites the instruction pointer, point it at your code,
and land execution in shellcode.

**How to test:**
- Send a cyclic/De Bruijn pattern, crash it, and read the value in
  EIP/RIP to compute the exact offset.
- Overwrite the pointer with a controlled address and place shellcode
  after it, padded with a NOP sled.
- Account for protections (DEP/ASLR/stack canaries) that change the
  approach.

**My notes:**


---

## Further reading - real disclosed reports referenced above

- https://medium.com/bugbountywriteup/a-five-minute-sql-i-16ab75b20fe4 - basic SQLi
- https://blog.securitybreached.org/2018/09/10/sqli-login-bypass-autotraders/ - login bypass via SQLi
- https://medium.com/@tomnomnom/making-a-blind-sql-injection-a-little-less-blind-428dcb614ba8 - blind SQLi
- https://medium.com/@frostnull1337/sql-injection-through-user-agent-44a1150f6888 - header-based SQLi
- https://logicbomb.medium.com/bugbounty-database-hacked-of-indias-popular-sports-company-bypassing-host-header-to-sql-7b9af997c610 - Host header SQLi
- https://mahmoudsec.blogspot.com/2018/07/sql-injection-and-silly-waf.html - WAF bypass SQLi
- https://blog.redforce.io/sql-injection-in-insert-update-query-without-comma/ - comma-restricted SQLi
- https://medium.com/@kgaber99/sql-injection-in-forget-password-function-3c945512e3cb - reset-function SQLi
- https://jspin.re/fileupload-blind-sqli/ - filename SQLi
- https://medium.com/bugbountywriteup/sql-injection-with-load-file-and-into-outfile-c62f7d92c4e2 - SQLi to RCE
- https://blog.yappare.com/2020/04/tricky-oracle-sql-injection-situation.html - Oracle SQLi
- https://medium.com/@St00rm/sql-injection-via-stopping-the-redirection-to-a-login-page-52b0792d5592 - redirect-gated SQLi
- http://hassankhanyusufzai.com/RFI_LFI_writeup/ - LFI basics
- https://medium.com/@maxon3/lfi-to-command-execution-deutche-telekom-bug-bounty-6fe0de7df7a6 - LFI log poisoning
- https://www.rcesecurity.com/2017/08/from-lfi-to-rce-via-php-sessions/ - LFI via PHP sessions
- https://medium.com/@armaanpathan/chain-the-bugs-to-pwn-an-organisation-lfi-unrestricted-file-upload-remote-code-execution-93dfa78ecce - LFI + upload to RCE
- https://www.rapid7.com/blog/2019/02/19/stack-based-buffer-overflow-attacks-what-you-need-to-know/ - buffer overflow basics
"""),

("07-Business-Logic", "Business Logic", """# Business Logic

These bugs don't show up in scanners - they require actually
understanding what the feature is supposed to do, then breaking that
assumption. This is the category where creativity pays the most, and
where the disclosed-report history is the richest source of ideas.

## [ ] 1. Race conditions

**What it is:** sending the same request multiple times simultaneously
to exploit a gap between "check" and "use" - the classic example is two
requests both reading "coupon not yet used" before either one has
finished marking it used, so both succeed.

**How to test:**
- Find any action that should only be usable once or a limited number
  of times (coupon redemption, invite acceptance, a limited-stock
  purchase, a one-time signup bonus, a gift card balance)
- Fire 10-20 identical requests at the exact same instant (Burp's "Send
  group in parallel" / Turbo Intruder, or a small Python asyncio script)
- Check if the action succeeded more times than it should have, or if
  a resource ended up in an impossible/inconsistent state

**Real-world creative scenarios (all from actual disclosed reports):**
1. **Redeem the same gift card multiple times for free money** (Reverb.com)
2. **Duplicate payment processing during a "retest" action** (HackerOne itself)
3. **Infinite in-game currency by racing an email-activation flow**
   (InnoGames) - the currency was granted on activation, and activation
   could be triggered repeatedly before the "already activated" flag
   was committed
4. **Redeeming coupon codes more than once** (Dropbox)
5. **Registering multiple accounts off one single-use invitation**
   (Keybase)
6. **Bypassing an invitation-count limit entirely via timing** (Keybase)
7. **Reviewing/rating something multiple times per user** (Coinbase)
8. **Bypassing a per-account subdomain creation limit** (Chaturbate)
9. **Adding the same team member twice, corrupting team state** (Shopify)
10. **Creating duplicate resources from a single "create" click** (Shopify)
11. **Duplicate payout triggered from one payout request** (HackerOne)
12. **Leaving a group member in an undeletable, broken state** (HackerOne)
13. **Stacking a loyalty/cashback bonus far beyond the intended amount**
    (Vend)
14. **Financial double-spend via balance TOCTOU** - a disclosed report
    showed that transfer/withdrawal endpoints checking balance, crediting
    the destination, then debiting the source can be raced so multiple
    concurrent requests all pass the balance check before any debit lands.
15. **TOCTOU on a temporarily-stored upload escalating to RCE** - a
    disclosed report found that racing requests to a predicted temp-file
    path during the brief window between upload and validation/deletion
    let a malicious file execute before cleanup removed it.
16. **Membership/state race for stealth access** - a disclosed Facebook
    Chat Groups report found that rapidly cycling add/remove membership
    left the account in a desynced state: present enough to read/write
    the conversation, but invisible to other members.

**Where to look on any target:** anything involving money, credits,
one-time codes, limited inventory, or "only once per account" rules is
worth a race-condition pass. Payment confirmation, coupon/promo
application, referral bonus claims, and free-trial activation are the
highest-density spots.

**My notes:**


---

## [ ] 2. Price, quantity, and currency manipulation

**What it is:** the client sends a price, quantity, or currency value
that the server trusts instead of recalculating from its own source of
truth.

**How to test:**
- Intercept the checkout/cart request and directly change price or
  quantity fields, see if the server recalculates or just trusts the client
- Try negative quantities, zero quantities, and fractional quantities
  where only integers make sense
- If the app supports multiple currencies, check whether an amount
  entered in one currency gets converted/validated correctly, or whether
  you can pay in a currency that's effectively worth less due to a
  conversion logic gap

**Real-world creative scenarios:**
1. **Total price manipulated via negative quantities** - a disclosed
   Upserve/OLO report found that setting a line-item quantity to a
   negative number reduced the total below zero, or below the sum of
   legitimate items.
2. **Price manipulation via fraction values** - a disclosed Shipt report
   found that sending a fractional value where the backend expected a
   whole number broke the price calculation in the attacker's favor.
3. **Currency arbitrage - pay less than the real USD price** - a
   disclosed PortSwigger report found a business logic flaw in currency
   conversion that let a purchase be completed for less than intended.
4. **Buy unlimited credits for a fraction of the price** - a disclosed
   report found an amount-manipulation bug letting an attacker purchase
   unlimited credits for a token amount.
5. **Extend an existing license's expiry by buying an unrelated add-on
   license** - a disclosed PortSwigger report found incorrect logic
   where buying one more license extended the expiration of a
   completely separate existing license.

**My notes:**


---

## [ ] 3. Plan / subscription / role logic bypass

**What it is:** getting access to a paid tier's features without
actually paying, by finding a code path that doesn't re-check the
subscription/role state.

**How to test:**
- Enumerate every feature gated "Pro only" / "Premium only" and test
  each one independently rather than assuming they all share one check
- Look for any endpoint that grants a feature via a *side effect* of
  another action (accepting an invite, changing a setting) rather than
  the direct upgrade flow - side-effect grants are far less likely to
  be re-validated

**Real-world creative scenarios:**
1. **Non-premium user changes retailer settings to get cashback across
   all retailers** - a disclosed Curve report found this exact gap.
2. **Extending a team beyond its paid size via the invitation flow** -
   a disclosed Infogram report found that the invite-acceptance path
   didn't re-check the team's plan limits.
3. **Using an iframe-embedding feature without the required upgrade** -
   another disclosed Infogram report; the iframe feature checked the
   plan at the UI layer only.
4. **Setting a "Read Access" role without a Pro subscription** - a
   disclosed report found the role-assignment endpoint didn't verify
   the acting user's plan before allowing it.

**My notes:**


---

## [ ] 4. HTTP method and response-trust confusion

**What it is:** access-control or business-rule checks that were applied
to one HTTP method (or one response field) but not consistently to all
of them.

**How to test:**
- Once you find a properly-blocked action via GET/POST, retry the exact
  same action via PUT, PATCH, and DELETE - middleware is sometimes
  registered per-method and simply missing on the less common ones
- After any gated action, check the server's response for a trust-me
  field (`success`, `allowed`, `role`) and see if editing that field in
  the response changes what the client does next

**Real-world creative scenarios:**
1. **PATCH request escalates API key permissions that POST/GET correctly
   block** (Frontegg, referenced in Authorization checklist too)
2. **Adding paid seats while paying for fewer, via a PUT request** - a
   disclosed Krisp report found that a PUT to a seats-management
   endpoint let more seats be added than were actually paid for.
3. **Response manipulation unlocks a paid product entirely client-side**
   (Logitech/Streamlabs, referenced in Authentication checklist too)

**My notes:**


---

## [ ] 5. Stale authorization / state not re-checked

**What it is:** a permission or piece of state that was correct at one
point in time, but never gets re-validated after the underlying
condition changes (a user is removed from a team, an item is deleted, a
session should have ended).

**How to test:**
- Remove/downgrade a test user from a group or role, then check whether
  they can still trigger actions or receive notifications tied to that
  membership
- Delete something, then check if any cached/stale reference to it still
  works (a "deleted" user's name still showing on hover, a "deleted"
  post still reachable by direct URL)
- Log out, then use the browser back button / cached page to see if
  authenticated content is still viewable

**Real-world creative scenarios:**
1. **Users who left a team still receive its notifications** - a
   disclosed HackerOne report found exactly this: authorization was
   checked when the notification setting was created, never again when
   it was sent.
2. **A deleted user's name still appears via a mouseover/tooltip** - a
   disclosed report found stale cached display data surviving deletion.
3. **Browser cache still shows authenticated content after logout** -
   disclosed against two separate programs (Localize, Certly) as its
   own distinct "business logic failure" category.

**My notes:**


---

## [ ] 6. Referral / invite / quota abuse

**What it is:** bonus, referral, and invitation systems assume good
faith about who is inviting whom and how many times - breaking that
assumption is usually cheap to test and can have real financial impact.

**How to test:**
- Try inviting yourself (a second test account) and see if a bonus
  triggers on both sides
- Try accepting the same invite link with multiple different accounts
- Check whether an invitation can be used to impersonate or silently
  attach to an existing user rather than creating a distinct new one

**Real-world creative scenario:** a disclosed WakaTime report found that
the invitation functionality could be abused to impersonate another
user outright, not just claim a bonus.

**My notes:**


---

## [ ] 7. Workflow / step skipping

**What it is:** jumping directly to a later step in a multi-step process
without completing the earlier ones.

**How to test:**
- Map the normal flow (step1 -> step2 -> step3 -> confirm)
- Try hitting step3 or the confirm endpoint directly without going
  through step1/step2

**My notes:**


---

## Further reading - real disclosed reports referenced above

- https://hackerone.com/reports/364843 - Total price manipulation via negative quantities (Upserve/OLO)
- https://hackerone.com/reports/388564 - Price manipulation via fraction values (Shipt)
- https://hackerone.com/reports/1677155 - Currency arbitrage, pay less than USD price (PortSwigger)
- https://hackerone.com/reports/277377 - Buy unlimited credits for $1 (Inflection)
- https://hackerone.com/reports/2461737 - Buying a license extends an unrelated license's expiry (PortSwigger)
- https://hackerone.com/reports/672487 - Non-premium user gets cashback on all retailers (Curve)
- https://hackerone.com/reports/295900 - Team invitation extends team size without upgrade (Infogram)
- https://hackerone.com/reports/594080 - Use iframe functionality without required upgrade (Infogram)
- https://hackerone.com/reports/3591764 - Set Read Access role without Pro subscription (Lovable)
- https://hackerone.com/reports/1446090 - Add seats while paying for fewer, via PUT request (Krisp)
- https://hackerone.com/reports/442843 - Removed users still receive notifications (HackerOne)
- https://hackerone.com/reports/127914 - Deleted name still present via mouseover (HackerOne)
- https://hackerone.com/reports/7909 / 158270 - Browser cache shows content after logout (Localize, Certly)
- https://hackerone.com/reports/257119 - Impersonation via invitation functionality (WakaTime)
- https://corneacristian.medium.com/top-25-race-condition-bug-bounty-reports-84f9073bf9e5 - race condition report roundup
- https://medium.com/swlh/hacking-banks-with-race-conditions-2f8d55b45a4b - financial double-spend
- https://infosecwriteups.com/race-condition-that-could-result-to-rce-a-story-with-an-app-that-temporary-stored-an-uploaded-9a4065368ba3 - TOCTOU upload to RCE
- https://www.seekurity.com/blog/general/the-fuzz-the-bug-the-action-a-race-condition-bug-in-facebook-chat-groups-leads-to-spy-on-conversations/ - membership state race
"""),

("08-CSRF-Clickjacking", "CSRF & Clickjacking", """# CSRF & Clickjacking

## [ ] 1. Missing or global token validation (site-wide CSRF)

**What it is:** the server never actually verifies the anti-CSRF token
on state-changing requests, or uses one global token that isn't bound
to the specific action, so a single forged request works across the
whole app.

**How to test:**
- Capture a state-changing request and replay it with the token
  parameter deleted entirely.
- Replay with the token emptied, or with characters altered but the
  same length.
- If it still succeeds, test several unrelated endpoints to prove the
  gap is site-wide.

**My notes:**


---

## [ ] 2. Downgrade the request method to skip the token check

**What it is:** the app enforces the CSRF token only on POST, so
switching the same action to a GET request (with all parameters in the
query string) skips validation entirely and can drive an account
takeover.

**How to test:**
- Take a protected POST action and resend it as GET with parameters in
  the URL.
- Drop the token parameter when you switch methods.
- If it works, weaponize as a simple URL that changes profile fields.

**My notes:**


---

## [ ] 3. JSON CSRF via content-type coercion

**What it is:** an API expects a JSON body but doesn't strictly validate
the Content-Type, so an auto-submitting HTML form with
`enctype="text/plain"` (or an X-HTTP-Method-Override trick) can deliver
a body the server parses as JSON - no token needed.

**How to test:**
- Build a form with `enctype="text/plain"` whose input name/value
  reconstructs the JSON payload.
- Append a dummy trailing key to absorb the `=` the browser inserts.
- Confirm the server accepts it without a valid Content-Type or token;
  try method-override headers if plain JSON is required.

**My notes:**


---

## [ ] 4. Reusable / non-expiring token

**What it is:** the token exists but never expires and isn't tied to
the session, so one token harvested once can be embedded in a CSRF PoC
and reused against many victims indefinitely.

**How to test:**
- Grab a token from your own session and build a PoC with it hardcoded.
- Fire the PoC from a different account/session and see if it's accepted.
- Wait/reuse over time to confirm it doesn't expire or rotate.

**My notes:**


---

## [ ] 5. Self-XSS + CSRF = stored XSS

**What it is:** an XSS that only fires in your own profile becomes a
real stored XSS when the field that holds it is changed via a
CSRF-vulnerable request - the attacker forces the victim's own account
to store the payload, which then runs for anyone viewing it.

**How to test:**
- Find an input that reflects/stores your script but is only
  self-visible.
- Check whether the endpoint that saves it lacks CSRF protection.
- Auto-submit a CSRF form that writes the payload into the victim's
  field; confirm it executes for other viewers.

**My notes:**


---

## [ ] 6. CORS misconfiguration enabling credentialed forgery

**What it is:** a server that reflects the Origin header with
Access-Control-Allow-Credentials: true (or trusts any subdomain) lets
attacker-controlled origins send authenticated cross-origin requests,
achieving CSRF-style state changes even against JSON APIs. See the CORS
checklist for the full test list.

**How to test:**
- Send requests with a crafted/foreign Origin and check if it's
  reflected with credentials allowed.
- Chain with a subdomain XSS to read cookies/tokens and issue the
  state-changing call.

**My notes:**


---

## [ ] 7. CSRF on destructive/unusual actions via GET (delete, logout, dismiss)

**What it is:** teams protect login/password forms but forget
destructive or "minor" actions - deleting media, logging users out,
dismissing reports - which are sometimes reachable by a plain GET and
trivially forged with a link or image.

**How to test:**
- Enumerate delete/remove/dismiss/logout endpoints and try them as GET.
- Drop tokens and see if the destructive action still fires.
- Deliver as a bare URL that the authenticated victim just has to load.

**My notes:**


---

## [ ] 8. CSRF that disables 2FA

**What it is:** the endpoint that turns off two-factor authentication
lacks CSRF protection, so a forged request silently strips the victim's
2FA and removes the barrier to a later takeover.

**How to test:**
- Locate the "disable 2FA" / "remove authenticator" request and build a
  CSRF PoC.
- Remove or reuse the token and confirm 2FA is turned off without
  interaction.
- Chain with a password-reset follow-up to demonstrate real impact.

**My notes:**


---

## [ ] 9. CSRF chained to OAuth access-token theft

**What it is:** a CSRF-reachable callback/test endpoint combined with a
loose (prefix-match) redirect_uri lets an attacker redirect a victim's
OAuth authorization code/token to an attacker-controlled URL, stealing
the integration's access.

**How to test:**
- Look for OAuth flows that accept partial redirect_uri matches instead
  of exact URLs.
- Find any CSRF-vulnerable endpoint under that allowed path that echoes
  or forwards parameters.
- Craft an authorize URL whose redirect lands on that endpoint and
  forwards the code to your server.

**My notes:**


---

## [ ] 10. Missing frame protection -> clickjacked account change

**What it is:** a sensitive page (like the profile/email-change form)
ships without X-Frame-Options/CSP frame-ancestors, so it can be framed
invisibly and the victim's real clicks are stolen to submit an
account-changing action.

**How to test:**
- Check for frame protection headers on settings and profile pages.
- If absent, frame the page at opacity 0 and align a decoy button over
  the real "Update" button.
- Pre-fill sensitive fields via URL parameters so one click completes
  the change; chain to password reset for takeover.

**My notes:**


---

## [ ] 11. Clickjacking with a CSP/frame-protection bypass

**What it is:** even when a high-value page tries to block framing, a
malformed value injected into an origin-type parameter (e.g. a
URL-encoded CR) can break the CSP check and re-enable framing of a
privileged action.

**How to test:**
- Identify parameters reflected into the framing/CSP logic.
- Inject encoded control characters or extra subdomains to see if the
  frame block drops.
- If framable, target a privilege-changing UI action.

**My notes:**


---

## [ ] 12. Bypassing JS frame-busting with an HTML5 sandbox iframe

**What it is:** when a page relies on JavaScript frame-busting instead
of the X-Frame-Options header, wrapping it in a `sandbox` iframe
(omitting `allow-top-navigation`) neuters the escape script while
keeping the page interactive.

**How to test:**
- Confirm the only defense is JS frame-busting, not a response header.
- Frame the page with a sandbox attribute that allows forms/scripts but
  not top-navigation.
- Verify the page still functions while unable to break out of the frame.

**My notes:**


---

## [ ] 13. Framing a token-leaking JSON/AJAX endpoint

**What it is:** the HTML page is frame-protected, but an AJAX variant
returns the same data as JSON without the header, so it can be framed
and used in a redress trick to leak OAuth/application tokens.

**How to test:**
- Take a protected page and request its API/AJAX form.
- Check whether the JSON response drops frame protection and exposes
  tokens.
- Frame it and social-engineer the victim into surfacing the token.

**My notes:**


---

## [ ] 14. Clickjacking to bypass CSRF by harvesting a valid token

**What it is:** when a state-changing request needs a token but an
endpoint discloses that token and the site is framable, the attacker
frames the disclosing page, tricks the victim into surfacing the token,
then submits it with malicious parameters.

**How to test:**
- Find any endpoint/response that leaks the current CSRF token.
- Confirm the site allows framing.
- Build a decoy that pulls the framed token into a hidden form and
  submits the account-change request.

**My notes:**


---

## [ ] 15. Clickjacking + self-XSS chain

**What it is:** a self-only XSS becomes exploitable when the payload
can be published to a public URL and that page lacks frame protection -
the attacker frames it and uses redressed clicks to fire the stored
script on the victim.

**How to test:**
- Inject a script payload into a field only you control, then publish
  it to a public URL.
- Confirm the published page has no frame protection.
- Frame it, position it over decoy targets, and require the clicks
  needed to trigger the payload.

**My notes:**


---

## Further reading - real disclosed reports referenced above

- https://whitton.io/articles/messenger-site-wide-csrf/ - site-wide CSRF
- https://medium.com/@Skylinearafat/a-very-useful-technique-to-bypass-the-csrf-protection-for-fun-and-profit-471af64da276 - method downgrade CSRF
- https://medium.com/@pig.wig45/json-csrf-attack-on-a-social-networking-site-hackerone-platform-3d7aed3239b0 - JSON CSRF
- https://medium.com/@renwa/self-xss-csrf-to-stored-xss-54f9f423a7f1 - self-XSS + CSRF
- https://medium.com/@osamaavvan/cors-to-csrf-attack-c33a595d441 - CORS to CSRF
- https://www.darabi.me/2019/12/instagram-delete-media-csrf.html - GET-based destructive CSRF
- https://vbharad.medium.com/2-fa-bypass-via-csrf-attack-8f2f6a6e3871 - CSRF disables 2FA
- https://arbazhussain.medium.com/stealing-access-token-of-one-drive-integration-by-chaining-csrf-vulnerability-779f999624a7 - CSRF to OAuth token theft
- https://medium.com/@osamaavvan/account-taker-with-clickjacking-ace744842ec3 - clickjacked account change
- https://apapedulimu.click/clickjacking-on-google-myaccount-worth-7500/ - CSP bypass clickjacking
- https://medium.com/@ameerassadi/binary-com-clickjacking-vulnerability-exploiting-html5-security-features-368c1ff2219d - sandbox iframe bypass
- https://www.seekurity.com/blog/general/redressing-instagram-leaking-application-tokens-via-instagram-clickjacking-vulnerability/ - AJAX endpoint framing
- https://saadahmedx.medium.com/bypass-csrf-with-clickjacking-worth-1250-6c70cc263f40 - clickjacking to bypass CSRF
- https://websecblog.com/vulns/clickjacking-xss-on-google-org/ - clickjacking + self-XSS
"""),

("09-SSRF", "Server-Side Request Forgery (SSRF)", """# Server-Side Request Forgery (SSRF)

## [ ] 1. SSRF via HTML-to-PDF / document generator

**What it is:** a feature that renders user-supplied text into a PDF
(or other document) processes embedded HTML server-side. Injecting
`<iframe>`/`<img>` tags makes the rendering engine fetch attacker-chosen
URLs, including `file://` for local file read, which can escalate to
RCE if it exposes SSH keys or runs as root.

**How to test:**
- Find any "export/save as PDF", invoice, or report generator that
  echoes your input.
- Inject `<iframe src="http://YOUR-COLLAB"></iframe>` and watch for the
  callback.
- Swap to `<iframe src="file:///etc/passwd">` to read local files.
- Try input via a secondary client (mobile app/API) if the web form
  filters HTML.

**My notes:**


---

## [ ] 2. SSRF via URL-fetch parameter reaching cloud metadata

**What it is:** an endpoint that fetches a user-supplied URL (image
proxy, link preview, webhook, "import from URL") with no host
validation can be pointed at `169.254.169.254` to steal IAM credentials
and pivot into the cloud account.

**How to test:**
- Locate params like `?url=`, `?image=`, `?callback=`, `?webhook=`.
- Point at your collaborator first to confirm outbound requests.
- Try `file:///etc/passwd`, then `http://169.254.169.254/latest/meta-data/`.
- Pull `iam/security-credentials/<role>`; export the keys and run `aws
  sts get-caller-identity`.

**My notes:**


---

## [ ] 3. SSRF filter bypass via DNS rebinding (TOCTOU)

**What it is:** when a server validates a hostname's IP against a
blocklist and then makes a second DNS lookup for the actual request, an
attacker-controlled DNS name that flips between a public IP and
`127.0.0.1` slips past the check.

**How to test:**
- Confirm the target resolves the hostname twice (validation + fetch).
- Use a rebinding domain that alternates a whitelisted IP and
  `127.0.0.1`, TTL 0.
- Fire the request many times to hit the winning race, then read
  internal content/metadata.

**My notes:**


---

## [ ] 4. SSRF filter bypass via open redirect on a whitelisted domain

**What it is:** if SSRF validation only allows a trusted partner/CDN
host but that host has an open redirect and the fetcher follows
redirects, you chain the redirect to reach arbitrary internal URLs.

**How to test:**
- Identify the allowed/whitelisted host the feature will fetch.
- Find an open redirect on that host.
- Feed the whitelisted redirect URL that bounces to an internal target;
  confirm the fetcher follows.

**My notes:**


---

## [ ] 5. Blind SSRF with OOB detection and response exfiltration

**What it is:** when SSRF gives no visible response, an out-of-band
callback proves it, and (where code injection exists) chaining
`fetch().then()` promises can exfiltrate the internal response body to
your server.

**How to test:**
- Inject your Burp Collaborator / OOB URL and watch for DNS/HTTP hits.
- If a JS/eval sink is reachable, chain a fetch that reads the internal
  response and re-sends it to your server.
- Also check misconfigured error-reporting agents (e.g. Sentry) that
  fetch attacker-supplied URLs.

**My notes:**


---

## [ ] 6. SSRF via gopher:// to internal TCP services

**What it is:** the `gopher://` protocol lets SSRF send arbitrary bytes
to internal TCP services (SMTP, Redis, etc.), turning a simple fetch
into full protocol interaction.

**How to test:**
- Test if the fetcher accepts `gopher://127.0.0.1:25/`.
- If direct gopher is blocked, host a redirect on your server that
  points to the gopher payload.
- URL-encode protocol commands into the gopher string and confirm
  delivery.

**My notes:**


---

## [ ] 7. SSRF via media/transcoding processing (FFmpeg, video upload)

**What it is:** media processors like FFmpeg follow URLs embedded
inside uploaded files (HLS playlists, crafted AVI). Uploading a file
that references internal URLs makes the server fetch them during
transcoding.

**How to test:**
- Find upload features that transcode video/audio or accept a media URL.
- Craft a file with an embedded internal/collaborator URL reference.
- Upload and watch for the server-side callback; escalate to `file://`
  reads where supported.

**My notes:**


---

## [ ] 8. Internal network / port scanning via SSRF

**What it is:** using the SSRF to probe internal-only services.

**How to test:**
- Point the vulnerable parameter at common internal ports (Redis,
  Elasticsearch, etc.) and compare response times/errors to find what's
  listening.

**My notes:**


---
"""),

("10-Subdomain-Takeover", "Subdomain Takeover", """# Subdomain Takeover

## [ ] 1. Dangling CNAME to an unclaimed S3 bucket

**What it is:** a subdomain CNAMEs to an S3 bucket that no longer
exists; the bucket name is free to register, so you claim it and serve
your own content on the target's subdomain.

**How to test:**
- Resolve subdomains and look for CNAMEs to `*.s3*.amazonaws.com`.
- Browse the subdomain - an `NoSuchBucket` error signals it's claimable.
- Create a bucket with the exact referenced name in the right region
  and host a proof file.

**My notes:**


---

## [ ] 2. Dangling CNAME to an unclaimed SaaS/PaaS site

**What it is:** a subdomain points to a hosting/marketing platform where
the account/site was deleted or never configured. Registering that
custom domain in your own account on the same provider takes over the
subdomain. Providers seen in real reports: Pantheon, HubSpot, Wufoo,
Shopify, Campaign Monitor.

**How to test:**
- Match the CNAME target and the platform-specific fingerprint/error
  page.
- Create an account on that provider and add the target domain as a
  custom/verified domain.
- Confirm your content now loads on the subdomain.

**My notes:**


---

## [ ] 3. Dangling CNAME to GitHub Pages / CloudFront

**What it is:** subdomains pointing at GitHub Pages or a decommissioned
CloudFront distribution can be reclaimed by creating a repo/Pages site
(or CloudFront alt-domain) with the target hostname.

**How to test:**
- Look for CNAMEs to `*.github.io` (404 "There isn't a GitHub Pages
  site here") or CloudFront distributions returning a claimable error.
- For GitHub Pages, create a repo, add the subdomain as the custom
  domain via a `CNAME` file, and enable Pages.
- Verify the takeover with a hosted proof page.

**My notes:**


---

## [ ] 4. Escalate takeover to SSO / auth bypass via shared cookie scope

**What it is:** when session cookies are scoped to the parent domain,
controlling any subdomain lets you read or set the parent's auth
cookies, defeating the whole SSO. See the Authentication checklist for
the follow-on session-theft steps.

**How to test:**
- After takeover, check whether auth cookies carry the parent domain
  scope.
- Host a page on the taken-over subdomain that reads incoming cookies
  or sets a forged session.
- Demonstrate reaching an authenticated area of the main SSO with those
  cookies.

**My notes:**


---

## [ ] 5. Escalate takeover to cookie/OAuth theft via same-origin trust

**What it is:** a taken-over subdomain is same-site with the parent, so
tricks like matching `document.domain`, permissive CORS wildcards, or
bypassed frame protections let you read parent DOM/cookies or steal
OAuth tokens.

**How to test:**
- Host JS on the taken-over subdomain; if the parent sets
  `document.domain`, set the same and read parent resources.
- Check for CORS reflecting any subdomain origin.
- Look for OAuth flows that whitelist subdomain redirect URIs you now
  control.

**My notes:**


---

## [ ] 6. Mass / automated takeover discovery

**What it is:** rather than one host, enumerate huge DNS datasets and
fingerprint dangling records at scale, including wildcard records that
resolve every possible subdomain to a claimable service.

**How to test:**
- Pull large subdomain sets (certificate transparency, DNS dumps) and
  resolve CNAMEs in bulk.
- Match against a known fingerprint list (subjack/nuclei takeover
  templates).
- Check wildcard CNAMEs, which expose unlimited claimable hostnames.

**My notes:**


---
"""),

("11-Remote-Code-Execution", "Remote Code Execution (RCE)", """# Remote Code Execution (RCE)

## [ ] 1. Unrestricted File Upload to Web Shell

**What it is:** an upload feature accepts executable server-side files
(.php, .jsp, .aspx) with no real validation, so you drop a shell and
browse to it.

**How to test:**
- Upload a `.php`/`.phtml`/`.aspx` file with a simple command-execution
  payload
- If blocked, try double extensions, case tricks, null bytes, or
  content-type spoofing
- Find where the file lands and request it directly to run commands

**My notes:**


---

## [ ] 2. PHP Code Hidden Inside a Re-Processed Image (GD Polyglot)

**What it is:** apps that re-encode uploads with PHP-GD usually strip
injected code, but certain image structures survive re-processing,
letting you smuggle PHP through an "image is validated" filter.

**How to test:**
- Craft a GIF with PHP inside a structure that survives GD recreation
- Get the file stored or renamed with a `.php` extension
- Request it to trigger execution

**My notes:**


---

## [ ] 3. RCE via Vulnerable Image Processing Library (ImageMagick / ImageTragick)

**What it is:** backend image libraries (ImageMagick, CVE-2016-3714
"ImageTragick") pass image contents to shell handlers, so a crafted
image file executes commands during processing.

**How to test:**
- Anywhere an image is uploaded/converted, submit a crafted polyglot
  with a command-delivery payload
- Use an out-of-band callback to confirm blind execution
- Also test URL-based image fetch fields, not just file uploads

**My notes:**


---

## [ ] 4. Path Traversal During Upload Writes a Shell to the Web Root

**What it is:** the upload filename or path parameter isn't sanitized,
so `../` sequences let you place your file in a web-executable
directory.

**How to test:**
- Inject `../../` into the filename or a path/directory parameter of
  the upload request
- Aim the write at a known web-served folder, then request the file
- Watch error messages - they often leak the resolved storage path

**My notes:**


---

## [ ] 5. IIS web.config Upload to RCE

**What it is:** on IIS, uploading a `web.config` into a directory can
enable server-side scripting (ASP classic) in that folder, giving code
execution without needing a blocked `.aspx` extension.

**How to test:**
- In any folder you can upload to on IIS, drop a `web.config` that
  enables ASP and embeds inline script
- Extension filters rarely block `web.config` since it's a "config" not
  a "script"

**My notes:**


---

## [ ] 6. Python SSTI (Jinja2 / Flask) to RCE

**What it is:** user input rendered as a Jinja2 template lets you walk
Python's object model to reach OS functions and read files or run
commands.

**How to test:**
- Probe reflected fields with `{{7*7}}` -> expects `49`
- Enumerate with `{{ [].__class__.__base__.__subclasses__() }}`
- Reach file/OS objects via subclass indexing to run commands or read
  files

**My notes:**


---

## [ ] 7. Node.js Template Injection (Handlebars / Mustache) to RCE

**What it is:** server-side JS template engines can be pushed to the
`Function` constructor, turning a template field into arbitrary JS
execution.

**How to test:**
- Fingerprint the engine first with basic template expressions
- For Handlebars, abuse `#each`/`Object.prototype` + `Function`
  constructor to break out of the compiled scope
- Target any email/notification template builder

**My notes:**


---

## [ ] 8. Java Template / EL Injection to RCE via Reflection (HubL, Freemarker)

**What it is:** Java-based template/expression languages expose
`getClass()`, letting you use reflection to instantiate a scripting
engine and run arbitrary Java.

**How to test:**
- Confirm evaluation with `{{7*7}}` and test `.getClass()` to detect Java
- Pivot through `javax.script.ScriptEngineManager` -> Nashorn `eval()`
  if `Runtime` is blocked
- Run a process builder inside the JS engine and capture output

**My notes:**


---

## [ ] 9. LaTeX Injection to RCE

**What it is:** apps that render user input into PDFs via LaTeX can be
pushed to shell-escape or file primitives, giving command execution or
file read/write.

**How to test:**
- In any "export to PDF"/formula/resume field, test file-read commands
- Try shell-escape commands if `--shell-escape` is enabled
- Use alternate include commands if primary ones are filtered

**My notes:**


---

## [ ] 10. SSRF Escalated to RCE

**What it is:** a server-side fetch primitive is pushed past simple URL
fetching into `file://` reads, internal-service access, or credential
theft that leads to a shell. See the SSRF checklist for the initial
discovery steps.

**How to test:**
- Turn SSRF into local file read - worse if the service runs as root
- Read cloud metadata / internal admin endpoints reachable only from
  the server
- Chain stolen keys/creds into SSH or an internal RCE-capable service

**My notes:**


---

## [ ] 11. Low-Priv Admin Panel to Code File Write (Magento / WooCommerce)

**What it is:** a limited CMS admin can combine a benign file-upload
feature with a path-traversal / template-include bug to get a PHP file
executed.

**How to test:**
- With low admin rights, upload a payload via a "custom option"/media
  feature
- Find a template/layout field that includes files by path and point
  it at your upload with traversal
- Note predictable storage paths leaked in errors

**My notes:**


---

## [ ] 12. Command Injection via Unsanitized Shell Parameters

**What it is:** a parameter is passed straight into a shell `exec()`
without escaping, so shell metacharacters run your commands.

**How to test:**
- Find endpoints that shell out (report/crash/PDF/network tools);
  inject shell metacharacters
- Use out-of-band exfil for blind cases
- Look at legacy/unauthenticated endpoints that predate hardening

**My notes:**


---

## [ ] 13. Exposed Jenkins Script Console to RCE

**What it is:** an internet-reachable Jenkins with open signup or no
auth exposes `/script` (Groovy console) = instant command execution.

**How to test:**
- Find Jenkins on odd ports via Shodan
- Check for "create account" on the login page or fully anonymous access
- At `/script` run a Groovy one-liner that executes a shell command

**My notes:**


---

## [ ] 14. Exposed AEM Felix Console + OSGi Bundle to RCE

**What it is:** Adobe AEM's admin/Felix console left reachable (often
behind a dispatcher-filter bypass and default creds) lets you install a
malicious OSGi bundle that runs commands.

**How to test:**
- Bypass dispatcher filters by appending harmless-looking extensions to
  protected paths
- Try default Basic auth credentials on the console
- Upload an OSGi bundle exposing a command-execution servlet

**My notes:**


---

## [ ] 15. Exposed Cluster Orchestrator API to RCE (Marathon / Mesos)

**What it is:** unauthenticated orchestration dashboards let you
schedule a container/task running any command - usually as root.

**How to test:**
- Find open Marathon/Mesos/Kubernetes/Consul UIs
- POST an app definition whose command exfiltrates command output for
  OOB proof
- Remember tasks typically run as root on the node

**My notes:**


---

## [ ] 16. Debug Mode / Verbose Errors Leaking Secrets to RCE

**What it is:** production debug pages (Rails, Werkzeug, Django debug)
leak secret keys or an interactive console that convert into code
execution.

**How to test:**
- Trigger exceptions with malformed input and read the debug page
- Grab a framework secret and forge a signed cookie that deserializes
  to a command
- For Werkzeug, try the PIN-protected console

**My notes:**


---

## [ ] 17. Insecure Deserialization to RCE (.NET SharePoint Workflows / Java)

**What it is:** untrusted serialized data (ViewState, workflow
definitions, Java objects) is deserialized server-side, letting crafted
gadget chains run code.

**How to test:**
- Look for base64/serialized blobs in params, cookies, ViewState, or
  workflow definitions
- For .NET, test known machineKey / gadget chains; for Java, ysoserial
- SharePoint workflow features accepting markup are a classic sink

**My notes:**


---

## [ ] 18. Chaining Low-Severity Bugs into RCE

**What it is:** no single critical bug - instead SSRF/XXE/upload/
leaked-source/admin-access are stacked, each step unlocking the next
until you reach code execution.

**How to test:**
- Map every "minor" finding (info leak, SSRF, weak upload, exposed
  source) as a potential chain link
- Use leaked source/secrets to find the real sink; use SSRF/XXE to
  reach internal RCE services
- Classic pattern: auth-bypass -> admin -> theme/plugin editor -> RCE

**My notes:**


---

## [ ] 19. Desktop App URI-Handler / Argument Injection to RCE

**What it is:** a registered custom URL scheme passes attacker-
controlled paths/args to the app, and path traversal or arg injection
triggers execution of an arbitrary file.

**How to test:**
- Enumerate an app's custom URI handlers and their parameters
- Inject traversal or extra CLI arguments into those params
- On macOS, escaping to an app bundle opened via a shell-execute
  primitive gives one-click RCE

**My notes:**


---

## [ ] 20. Sandboxed Editor / eval Feature Escape to RCE

**What it is:** features that run user code in a "sandbox" (online
IDEs, formula/scripting fields, template previews) can often be broken
out of to reach the host OS.

**How to test:**
- In any code-runner/eval field, enumerate reachable language internals
- Attempt to import OS/process modules or reach a scripting engine the
  sandbox forgot to block
- Confirm with an out-of-band callback rather than relying on visible
  output

**My notes:**


---

## Further reading - real disclosed reports referenced above

- https://blog.securitybreached.org/2017/12/19/unrestricted-file-upload-to-rce-bug-bounty-poc/ - file upload to shell
- https://asdqw3.medium.com/remote-image-upload-leads-to-rce-inject-malicious-code-to-php-gd-image-90e1e8b2aada - GD polyglot
- https://strynx.org/imagemagick-rce/ - ImageTragick
- https://blog.harshjaiswal.com/path-traversal-while-uploading-results-in-rce - path traversal upload
- https://poc-server.com/blog/2018/05/22/rce-by-uploading-a-web-config/ - IIS web.config
- https://akshukatkar.medium.com/rce-with-flask-jinja-template-injection-ea5d0201b870 - Jinja2 SSTI
- https://mahmoudsec.blogspot.com/2019/04/handlebars-template-injection-and-rce.html - Handlebars SSTI
- https://www.betterhacker.com/2018/12/rce-in-hubspot-with-el-injection-in-hubl.html - Java EL injection
- https://medium.com/bugbountywriteup/latex-to-rce-private-bug-bounty-program-6a0b5b33d26a - LaTeX injection
- https://medium.com/@armaanpathan/pdfreacter-ssrf-to-root-level-local-file-read-which-led-to-rce-eb460ffb3129 - SSRF to RCE
- https://blog.scrt.ch/2019/01/24/magento-rce-local-file-read-with-low-privilege-admin-rights/ - Magento low-priv RCE
- https://www.rcesecurity.com/2019/04/dell-kace-k1000-remote-code-execution-the-story-of-bug-k1-18652/ - command injection
- https://medium.com/@sw33tlie/finding-a-p1-in-one-minute-with-shodan-io-rce-735e08123f52 - exposed Jenkins
- https://medium.com/@byq/how-to-get-rce-on-aem-instance-without-java-knowledge-a995ceab0a83 - AEM console
- https://omespino.com/write-up-private-bug-bounty-usd-rce-as-root-on-marathon-instance/ - exposed orchestrator
- https://sites.google.com/view/harshjaiswalblog/rce-due-to-showexceptions - debug mode leak
- https://soroush.me/blog/2018/12/story-of-two-published-rces-in-sharepoint-workflows/ - insecure deserialization
- https://blog.orange.tw/2018/08/how-i-chained-4-bugs-features-into-rce-on-amazon.html - bug chaining
- https://0xacb.com/2018/12/04/github-desktop-rce/ - URI handler RCE
- https://jatindhankhar.in/blog/responsible-disclosure-breaking-out-of-a-sandboxed-editor-to-perform-rce/ - sandbox escape
"""),

("12-API-GraphQL", "API & GraphQL Testing", """# API & GraphQL Testing

## [ ] 1. GraphQL introspection enabled

**What it is:** the schema (every type, field, mutation) being fully
queryable, handing you the entire API map.

**How to test:**
- POST the standard introspection query to the GraphQL endpoint
- If it returns the full schema in production, that's worth noting
  (though often low severity alone - value comes from what you find
  IN the schema, like an admin mutation)

**My notes:**


---

## [ ] 2. Batching / query cost abuse

**What it is:** GraphQL lets you request deeply nested or repeated data
in one call, which can be abused for brute-forcing or resource exhaustion.

**How to test:**
- Try aliasing the same login/lookup mutation dozens of times in one
  request to bypass simple rate limiting (each alias = one attempt,
  one HTTP request)

**My notes:**


---

## [ ] 3. Old API versions still active

**What it is:** a v1 endpoint that was supposed to be retired when v2
shipped, but still works with weaker auth/validation.

**How to test:**
- If you find /api/v2/resource, always try /api/v1/resource,
  /api/resource, and any other version-looking prefix

**My notes:**


---

## [ ] 4. Mass assignment via API

**What it is:** same as the general mass assignment test, but focused on
JSON API bodies where it's easy to add fields.

**How to test:**
- Take a real API request and add fields not in the documented schema:
  role, isAdmin, ownerId, status

**My notes:**


---

## [ ] 5. Broken Object Level Authorization (BOLA) on API endpoints

**What it is:** the API equivalent of IDOR - same test, applied
systematically across every endpoint that takes an ID.

**How to test:**
- Map every API endpoint that accepts an ID parameter
- For each one, test with two accounts and swap IDs
- A disclosed TikTok report found IDOR specifically in a report-download
  endpoint - export/download features are a strong place to focus since
  they're often built later and separately from the main CRUD endpoints

**My notes:**


---
"""),

("13-File-Upload", "File Upload", """# File Upload

## [ ] 1. File type / extension bypass

**What it is:** upload filters that check the extension or MIME type but
can be tricked.

**How to test:**
- Try double extensions (shell.php.jpg), null byte tricks, uppercase
  extensions (.PHP), changing only the Content-Type header while
  keeping a malicious body

**My notes:**


---

## [ ] 2. Path traversal in filename

**What it is:** a filename field that lets you control where the file
gets saved.

**How to test:**
- Set the filename to `../../../somewhere/evil.php`

**My notes:**


---

## [ ] 3. Stored XSS via SVG or other XML-based formats

**What it is:** SVG files can contain embedded `<script>` tags that
execute when the "image" is viewed.

**How to test:**
- Upload an SVG containing a script tag as a profile picture / attachment
  and see if it executes when viewed

**My notes:**


---

## [ ] 4. Malicious file leading to execution

**What it is:** confirming whether an uploaded file can actually be
executed by the server (the highest-impact version of file upload bugs).
See the RCE checklist for the full follow-on escalation techniques once
a file lands.

**How to test:**
- Only pursue this if you have a legitimate path to get a webshell-type
  file uploaded and reachable - requires the upload directory to be
  both writable and served/executable

**My notes:**


---

## [ ] 5. Upload-based resource exhaustion

**What it is:** whether the app enforces file size/type limits at all.

**How to test:**
- Try a very large file, or a "zip bomb" style compressed file if
  the app processes archives

**My notes:**


---
"""),

("14-CORS", "CORS Misconfiguration", """# CORS Misconfiguration

CORS deserves its own dedicated pass since it's genuinely technique-rich,
not just "check for a wildcard" - and it chains directly into CSRF and
XSS categories worth cross-referencing.

## [ ] 1. Reflected arbitrary Origin with credentials

**What it is:** the server echoes whatever Origin it receives into
Access-Control-Allow-Origin and sets Access-Control-Allow-Credentials:
true, so any attacker page can make authenticated cross-origin reads and
steal private data.

**How to test:**
- Send requests with `Origin: https://evil.com` to authenticated API
  endpoints.
- Check whether the response reflects your origin and returns
  credentials allowed.
- Build a PoC page doing a credentialed fetch and confirm it reads the
  victim's data.

**My notes:**


---

## [ ] 2. Weak Origin-validation bypasses (prefix/suffix/substring/null)

**What it is:** the allowlist check is a naive substring/regex match,
so origins like `target.com.evil.com` (suffix), `eviltarget.com`
(prefix), `target.com` anywhere in the string, or `null` slip through
and get reflected with credentials.

**How to test:**
- Try Origin values with the target domain as a suffix, prefix, or
  substring of an attacker domain, and try `null` via a sandboxed
  iframe/redirect.
- See which are reflected into the allow-origin header.
- Confirm exploitability with a credentialed fetch from the accepted
  origin.

**My notes:**


---

## [ ] 3. Trusting all subdomains, then chaining subdomain XSS

**What it is:** CORS trusts every subdomain of the target; combined
with an XSS or takeover on any subdomain and cookies scoped to the
parent domain, the attacker runs credentialed cross-origin requests
from a "trusted" context. See the Subdomain Takeover checklist for the
claiming step.

**How to test:**
- Verify arbitrary subdomains are accepted in the allow-origin header
  with credentials.
- Find an XSS, open redirect, or takeover on any in-scope subdomain.
- From that subdomain, issue credentialed requests / read parent-scoped
  cookies.

**My notes:**


---

## [ ] 4. CORS enabling state-changing CSRF-style writes

**What it is:** permissive CORS on write endpoints lets attacker JS
send credentialed PUT/POST requests (and read anti-CSRF tokens first),
modifying account data even where classic CSRF defenses exist.

**How to test:**
- Identify state-changing endpoints reachable cross-origin with
  credentials.
- If a CSRF token is required, first read it via the CORS leak, then
  replay it in the write request.
- Confirm the account change lands.

**My notes:**


---

## [ ] 5. CORS/AJAX response reflected into the page -> XSS

**What it is:** a page fetches an attacker-influenced URL (weak domain
regex, e.g. unanchored match) and drops the CORS response into the DOM;
the attacker serves CORS-permissive HTML/JS that then executes in the
target's origin.

**How to test:**
- Find client-side fetches whose URL is derived from user input and
  validated by a loose (unanchored) regex.
- Point it at your host with a value that satisfies the regex.
- Serve permissive CORS headers plus an XSS payload and confirm
  execution via the rendering sink.

**My notes:**


---

## Further reading - real disclosed reports referenced above

- https://nahoragg.medium.com/a-simple-cors-misconfig-leaked-private-post-of-twitter-facebook-instagram-5f1a634feb9d - reflected origin
- https://infosecwriteups.com/pre-domain-wildcard-cors-exploitation-2d6ac1d4bd30 - weak origin validation
- https://medium.com/@osamaavvan/cors-to-csrf-attack-c33a595d441 - CORS chained to CSRF
- https://whitton.io/articles/abusing-cors-for-an-xss-on-flickr/ - CORS response to XSS
"""),

("15-Rate-Limiting-Anti-Automation", "Rate Limiting & Anti-Automation (incl. DoS)", """# Rate Limiting & Anti-Automation

Most programs exclude generic missing-rate-limiting reports, but almost
all of them explicitly carve authentication flows back into scope -
check the program rules first.

## [ ] 1. Rate limiting on authentication flows

**What it is:** login, registration, and password reset should all
throttle repeated attempts.

**How to test:**
- Send a bounded batch (10-30, not thousands) of requests to each flow
  and watch for any throttling signal
- Two disclosed reports (Infogram, Nextcloud) found exactly this on
  password-reset specifically - it's the single most commonly missed
  auth flow for rate limiting, likely because teams remember to protect
  login but treat "forgot password" as lower risk

**My notes:**


---

## [ ] 2. CAPTCHA bypass

**What it is:** see the detailed CAPTCHA test in the Authentication
checklist - repeated here because it's worth checking on every form
that has one, not just login.

**How to test:**
- Empty token vs garbage token vs omitted field entirely - compare
  error messages for each

**My notes:**


---

## [ ] 3. OTP / verification code brute force

**What it is:** a 4-6 digit code is a small enough space to brute force
if there's no rate limit or lockout.

**How to test:**
- Send several wrong codes in a row and see if anything stops you
  before you'd exhaust a realistic guessing range

**My notes:**


---

## [ ] 4. Report/moderation-action rate limiting

**What it is:** less obvious than login/reset, but "report this content"
or "flag this comment" type actions are often built without any
throttle at all, and can be chained into real abuse.

**How to test:**
- A disclosed report found that no rate limit on a "report" function
  let it be abused to auto-delete a comment once a threshold of reports
  was hit - test any moderation/flagging feature for both missing rate
  limits and whether the *count* itself can be gamed

**My notes:**


---

## [ ] 5. Notification / dialog flood DoS

**What it is:** abusing a feature that spawns a modal/popup (AirDrop
share prompt, push dialogs) by sending it in a tight loop makes the
device or UI unusable because each dismissal instantly regenerates the
prompt.

**How to test:**
- Identify a feature that triggers a blocking dialog on a target
  device/user.
- Send it repeatedly (e.g. opendrop for AirDrop) and observe the UI
  locking up.
- Note vulnerable settings (e.g. AirDrop "Everyone") that widen the
  attack surface.

**My notes:**


---

## [ ] 6. Application-level DoS via oversized string input

**What it is:** fields that get hashed or heavily processed (passwords,
names, comments) with no length cap let a single huge string exhaust
CPU/memory and crash the request handler.

**How to test:**
- Submit a very long string (50k-100k+ chars) into password, signup, or
  comment fields.
- Compare response times/status; a spike to 500 or hang indicates DoS.
- Focus on signup and password-reset where server-side hashing runs.

**My notes:**


---

## [ ] 7. Unauthenticated resource amplification

**What it is:** an endpoint that bundles/concatenates many
modules/assets per request can be asked to load everything at once,
unauthenticated, so a few requests spike server CPU and take the site
down (this exact pattern was CVE-2018-6389 in WordPress).

**How to test:**
- Find endpoints that accept a list of assets/modules to combine.
- Request the maximum module list repeatedly and watch server load.
- Note if it's unauthenticated and low-request - cheap to trigger.

**My notes:**


---

## [ ] 8. Client/app crash via malformed Unicode

**What it is:** rendering engines choke on large runs of special
characters, sending the app into an infinite loop or crash when it
displays the stored content - a persistent DoS.

**How to test:**
- Paste tens of thousands of special Unicode characters into a
  note/message/name field.
- Save/send, then open it in the target app (especially mobile).
- Look for freezes, infinite loops, or forced app restarts.

**My notes:**


---

## [ ] 9. Logic-based DoS via ambiguous/collision input

**What it is:** feeding input a system can't disambiguate breaks a
downstream operation for everyone - a disclosed GitHub Actions report
found a short commit hash that collided across forks, breaking all
builds referencing it.

**How to test:**
- Look for identifiers truncated or loosely parsed (short hashes,
  non-unique keys) that a shared service resolves.
- Craft a colliding/ambiguous value and confirm the resolving endpoint
  errors.
- Assess blast radius - does one bad value break a shared/global
  operation?

**My notes:**


---

## Further reading - real disclosed reports referenced above

- https://kishan.org/airdos/ - notification/dialog flood DoS
- https://medium.com/@shahjerry33/long-string-dos-6ba8ceab3aa0 - oversized string DoS
- https://www.pankajinfosec.com/post/700-denial-of-service-dos-vulnerability-in-script-loader-php-cve-2018-6389 - resource amplification
- https://rahulkankrale.medium.com/dos-on-facebook-android-app-using-65530-characters-of-zero-width-no-break-space-db41ca8ded89 - Unicode crash DoS
- https://blog.teddykatz.com/2019/11/12/github-actions-dos.html - logic-based collision DoS
"""),

("16-Server-Config-Misc", "Server Configuration & Misc", """# Server Configuration & Misc

## [ ] 1. Missing or weak security headers

**What it is:** headers like CSP, X-Content-Type-Options, HSTS -
usually low severity alone, but worth noting as supporting context.

**How to test:**
- Check response headers on key pages
- Remember: most programs explicitly exclude "missing header" reports
  unless you can show a concrete exploitable scenario

**My notes:**


---

## [ ] 2. Dangerous HTTP methods enabled

**What it is:** methods like TRACE, PUT, DELETE being accepted when
they shouldn't be.

**How to test:**
- OPTIONS request to see what's allowed, then try PUT/DELETE directly
  against a resource

**My notes:**


---

## [ ] 3. Verbose errors / stack trace disclosure

**What it is:** the app leaking internal file paths, class names, or
stack traces to an unauthenticated user - low severity alone, but often
a great source of leads for other bugs (real class/method names to
pivot on).

**How to test:**
- Send malformed input to any endpoint and see what comes back in the
  error - unexpected types, missing required fields, truncated JSON

**My notes:**


---
"""),

("17-Android-Pentesting", "Android Pentesting", """# Android Pentesting

## [ ] 1. Lab setup and HTTPS traffic interception

**What it is:** the baseline Android testing environment - a rooted
emulator/device plus an intercepting proxy - so you can see and tamper
with the app's API traffic, which is where most bugs actually live.

**How to test:**
- Run the app on a rooted emulator (Genymotion/AVD); route traffic
  through Burp/ZAP and install the proxy CA as a system-trusted cert.
- Defeat TLS/cert pinning with Frida/Objection so HTTPS is readable.
- Exercise the app and hunt IDOR/auth/business-logic bugs in the
  intercepted API calls (use the other checklists in this folder against
  the mobile API surface, not just the web one).

**My notes:**


---

## [ ] 2. Static + dynamic analysis of the APK

**What it is:** pull the APK apart to find hardcoded secrets,
endpoints, and insecure components, then hook the running app to bypass
client-side checks.

**How to test:**
- Decompile with apktool/jadx; grep for API keys, URLs, tokens, and
  debug flags; review exported activities/services/providers and local
  storage (shared_prefs, SQLite).
- Use Frida to hook methods (root/pinning/tamper checks, auth booleans)
  at runtime.
- Test exported components and deep links for unauthorized access.

**My notes:**


---
"""),
]

# One-line hook per category, shown next to its number in the picker menu.
TAGLINES = {
    "01-Recon": "Map the attack surface before you touch anything.",
    "02-Authentication": "The single highest-density area for real, payable bugs.",
    "03-Session-Management": "Tokens, cookies, and what survives logout.",
    "04-Authorization-Access-Control": "IDOR territory - consistently the most payable category.",
    "05-Cross-Site-Scripting": "20+ contexts, 24 real disclosed techniques.",
    "06-Injection": "SQLi, LFI, SSTI, XXE, command injection, buffer overflow.",
    "07-Business-Logic": "Scanners can't find these. Creativity pays the most here.",
    "08-CSRF-Clickjacking": "Forged requests and stolen clicks.",
    "09-SSRF": "Turn a URL fetch into cloud credential theft.",
    "10-Subdomain-Takeover": "Claim what the DNS forgot to clean up.",
    "11-Remote-Code-Execution": "The endgame - 20 real escalation paths.",
    "12-API-GraphQL": "Introspection, batching, BOLA.",
    "13-File-Upload": "What happens after the file lands.",
    "14-CORS": "Origin reflection, credentialed reads, chained XSS.",
    "15-Rate-Limiting-Anti-Automation": "Brute force, OTP spam, and app-level DoS.",
    "16-Server-Config-Misc": "Low severity alone, high value as supporting evidence.",
    "17-Android-Pentesting": "Rooted device, Frida, and the mobile API surface.",
}

# Shown once per run, picked at random - general hunting mindset, not tied
# to any one category.
TIPS = [
    "Think like an attacker with a specific goal, not a scanner looking for patterns.",
    "If a feature has auth checks, its newly-added sibling feature probably doesn't yet.",
    "Every 'only once' action - coupon, invite, discount - is worth a race-condition pass.",
    "A legacy endpoint sitting next to a modern one is often missing a control the modern one has.",
    "Don't stop at proving the bug exists - prove the business impact in dollars or users affected.",
    "Give each parameter a 20-45 minute timer. Stuck past that? Rotate, don't tunnel.",
    "One confirmed bug often means the same developer made a sibling mistake nearby - look for it.",
    "A client-side check is a UX nicety, not a security boundary - always verify server-side too.",
    "Read the response, not just the status code - a 200 with the wrong body is still a finding.",
    "The feature built last, and in a hurry, is usually the one with the gap.",
]

_COLOR_ENABLED = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def c(text, code):
    if not _COLOR_ENABLED:
        return text
    return f"\033[{code}m{text}\033[0m"


def bold(text):
    return c(text, "1")


def cyan(text):
    return c(text, "36")


def green(text):
    return c(text, "32")


def yellow(text):
    return c(text, "33")


def dim(text):
    return c(text, "2")


INDEX_TEMPLATE = """# {target} - Hunting Checklist

Started: {date}

Work through each category folder. Every item has an explanation of what
to test, how to test it, a list of creative real-world attack scenarios
(pulled from actual disclosed bug bounty reports, deduplicated and merged
by technique), and a spot for your notes right below it. Check the box
(`[ ]` -> `[x]`) as you go.

## Categories

{category_links}

## Other folders

- `notes/` - freeform scratch notes, not tied to a specific checklist item
- `findings/` - drop draft reports here as you confirm real bugs

## How to use this

1. Open a category file in your editor.
2. Pick an item, read the explanation and the creative scenarios list.
3. Write what you found directly under "My notes" for that item.
4. Check the box once you've actually tested it (checked != vulnerable,
   just means "tested").
5. Move confirmed bugs into `findings/` as their own file once you're
   ready to write them up properly.
6. Most categories end with a "Further reading" section - real links to
   the disclosed reports referenced. Worth reading a few end to end,
   they teach you how to think about the next target, not just this one.
"""

NOTES_TEMPLATE = """# {target} - General Notes

Freeform space for anything that doesn't belong to one specific
checklist item: stray observations, credentials for test accounts,
useful URLs, things to come back to later.

---

"""

FINDINGS_README = """# Findings

Drop one file per confirmed bug in here once you're ready to write it
up (e.g. `reset-password-captcha-bypass.md`). Keep exploration notes in
the category checklists or `notes/` - this folder is for things you're
actually confident are real and worth reporting.
"""


def safe_folder_name(name):
    """Strip characters that are invalid in Windows folder names."""
    name = name.strip()
    name = re.sub(r'[<>:"/\\|?*]', '-', name)
    return name or "untitled-target"


def write_if_missing(path, content):
    if os.path.exists(path):
        print(f"  skip (already exists): {path}")
        return
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"  created: {path}")


def item_count(body):
    return body.count("## [ ]")


def print_banner():
    print(bold(cyan("=" * 62)))
    print(bold(cyan("  BUG BOUNTY HUNTING CHECKLIST GENERATOR")))
    print(bold(cyan("=" * 62)))
    print(dim(f"  tip: {random.choice(TIPS)}"))
    print()


def print_category_menu():
    total_items = 0
    for idx, (folder, title, body) in enumerate(CATEGORIES, start=1):
        n = item_count(body)
        total_items += n
        tagline = TAGLINES.get(folder, "")
        num = yellow(f"{idx:>2}")
        print(f" {num}. {bold(title):<55} {dim(f'({n} items)')}")
        if tagline:
            print(f"     {dim(tagline)}")
    print()
    print(dim(f"  {len(CATEGORIES)} categories, {total_items} checklist items total"))
    print()


def parse_selection(raw, max_n):
    """Parse '1,3,5', '1-6', 'all'/'a', or a mix like '1-4,9,12' into a
    sorted list of unique 1-based indices. Returns None on 'all'/'a'/empty
    (meaning: everything)."""
    raw = raw.strip().lower()
    if raw in ("", "all", "a"):
        return None
    picked = set()
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start, _, end = chunk.partition("-")
            try:
                start_i, end_i = int(start), int(end)
            except ValueError:
                raise ValueError(f"Bad range: '{chunk}'")
            if start_i > end_i:
                start_i, end_i = end_i, start_i
            for i in range(start_i, end_i + 1):
                picked.add(i)
        else:
            try:
                picked.add(int(chunk))
            except ValueError:
                raise ValueError(f"Bad number: '{chunk}'")
    for i in picked:
        if i < 1 or i > max_n:
            raise ValueError(f"{i} is out of range (1-{max_n})")
    return sorted(picked)


def select_categories_interactive():
    print_category_menu()
    while True:
        raw = input(
            "Pick categories - comma list (1,3,5), a range (1-6), a mix "
            "(1-4,9,12), or Enter for all: "
        )
        try:
            indices = parse_selection(raw, len(CATEGORIES))
        except ValueError as e:
            print(f"  {yellow(str(e))} - try again.")
            continue
        break
    if indices is None:
        return list(CATEGORIES)
    return [CATEGORIES[i - 1] for i in indices]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate a bug bounty hunting checklist folder tree."
    )
    parser.add_argument("-n", "--name", help="target/project name (skips the prompt)")
    parser.add_argument(
        "-a", "--all", action="store_true", help="generate all categories, no picker"
    )
    parser.add_argument(
        "-c",
        "--categories",
        help="category numbers to generate, e.g. '2,4,5' or '1-6' or '1-4,9,12' "
        "(see -l for the numbered list)",
    )
    parser.add_argument(
        "-l",
        "--list",
        action="store_true",
        help="list all categories with item counts and exit",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["md", "txt"],
        help="output file extension for the checklists (default: md; skips the prompt)",
    )
    return parser.parse_args()


def select_format(args):
    if args.format:
        return args.format
    fully_scripted = bool(args.name) and (args.all or args.categories)
    if fully_scripted:
        return "md"
    raw = input(
        "Output format - 'md' (Markdown, recommended for GitHub/Obsidian/VS Code) "
        "or 'txt' (plain text)? [md]: "
    ).strip().lower()
    if raw in ("", "md", "markdown"):
        return "md"
    if raw in ("txt", "text"):
        return "txt"
    print(f"  {yellow('Unrecognized choice, defaulting to md.')}")
    return "md"


def main():
    args = parse_args()

    if args.list:
        print_banner()
        print_category_menu()
        return

    print_banner()

    raw_name = args.name.strip() if args.name else input("Enter target/project name: ").strip()
    if not raw_name:
        print("No name entered, aborting.")
        sys.exit(1)

    if args.all:
        selected = list(CATEGORIES)
    elif args.categories:
        try:
            indices = parse_selection(args.categories, len(CATEGORIES))
        except ValueError as e:
            print(f"{yellow(str(e))}")
            sys.exit(1)
        selected = list(CATEGORIES) if indices is None else [CATEGORIES[i - 1] for i in indices]
    else:
        selected = select_categories_interactive()

    chosen_titles = ", ".join(title for _, title, _ in selected)
    print(f"\n{green('Selected:')} {chosen_titles}\n")

    fmt = select_format(args)
    print(f"{green('Format:')} .{fmt}\n")

    target_name = safe_folder_name(raw_name)
    base_dir = os.path.join(os.getcwd(), target_name)

    print(f"Building checklist tree in: {base_dir}\n")
    os.makedirs(base_dir, exist_ok=True)

    # category folders + checklist files
    total_items = 0
    for folder, title, body in selected:
        cat_dir = os.path.join(base_dir, folder)
        os.makedirs(cat_dir, exist_ok=True)
        write_if_missing(os.path.join(cat_dir, f"checklist.{fmt}"), body)
        total_items += item_count(body)

    # notes/ and findings/
    notes_dir = os.path.join(base_dir, "notes")
    findings_dir = os.path.join(base_dir, "findings")
    os.makedirs(notes_dir, exist_ok=True)
    os.makedirs(findings_dir, exist_ok=True)
    write_if_missing(
        os.path.join(notes_dir, f"general-notes.{fmt}"),
        NOTES_TEMPLATE.format(target=raw_name),
    )
    write_if_missing(os.path.join(findings_dir, f"README.{fmt}"), FINDINGS_README)

    # Index reflects every category that actually exists on disk (not just
    # the ones picked this run), so running the script again later to add
    # more categories - even in the other format - keeps the index accurate
    # instead of going stale.
    category_links = []
    for folder, title, _ in CATEGORIES:
        for ext in (fmt, "md", "txt"):
            candidate = os.path.join(base_dir, folder, f"checklist.{ext}")
            if os.path.exists(candidate):
                category_links.append(f"- [{title}](./{folder}/checklist.{ext})")
                break
    index_content = INDEX_TEMPLATE.format(
        target=raw_name,
        date=datetime.date.today().isoformat(),
        category_links="\n".join(category_links),
    )
    index_path = os.path.join(base_dir, f"00-INDEX.{fmt}")
    with open(index_path, "w", encoding="utf-8") as f:
        f.write(index_content)
    print(f"  updated: {index_path}")

    print()
    cat_word = "category" if len(selected) == 1 else "categories"
    print(green(f"Done. {len(selected)} {cat_word} added, {total_items} checklist items ready."))
    print(f"Open {index_path} to start.")


if __name__ == "__main__":
    main()
