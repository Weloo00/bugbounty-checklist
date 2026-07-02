# bugbounty-checklist

A local checklist generator for bug bounty hunting. Run it, type a target
name, pick which vulnerability categories you want, and it builds a folder
tree of markdown (or plain text) checklists - each item explains what to
test, how to test it, and lists creative attack scenarios pulled from real,
disclosed bug bounty writeups (deduplicated and merged by technique, with
source links). There's a spot for your own notes under every single item.

No dependencies beyond Python 3. Nothing is uploaded anywhere - it just
writes files to your local disk.

## Usage

```bash
python3 bugbounty-checklist-init.py
```

Interactive mode: it asks for a target/project name, shows a numbered menu
of all 17 categories with a one-line description and item count for each,
and lets you pick which ones you want (comma list, range, or all), then
asks whether you want markdown or plain text output.

Non-interactive / scriptable:

```bash
# all 17 categories, defaults to markdown
python3 bugbounty-checklist-init.py -n my-target -a

# just a few categories by number
python3 bugbounty-checklist-init.py -n my-target -c 2,4,5,7,11

# a range, plain text output
python3 bugbounty-checklist-init.py -n my-target -c 1-6 -f txt

# see the full numbered category list with item counts, no folder created
python3 bugbounty-checklist-init.py -l
```

Run it again on the same target folder to add more categories later - it
never overwrites a file that already exists, so your notes are always
safe. The `00-INDEX.md` index is regenerated each run to reflect whatever
categories currently exist on disk.

## What you get

```
my-target/
  00-INDEX.md
  01-Recon/checklist.md
  02-Authentication/checklist.md
  ...
  17-Android-Pentesting/checklist.md
  notes/general-notes.md
  findings/README.md
```

## Categories

Recon, Authentication, Session Management, Authorization & Access Control,
Cross-Site Scripting, Injection (SQLi/LFI/SSTI/XXE/Command/Buffer
Overflow), Business Logic, CSRF & Clickjacking, SSRF, Subdomain Takeover,
Remote Code Execution, API & GraphQL, File Upload, CORS, Rate Limiting &
Anti-Automation, Server Configuration & Misc, Android Pentesting.

172 checklist items total across all categories, each grounded in a real
disclosed report rather than invented from scratch.
