# Recording the 90-second demo

`RUNBOOK.md` is the 30-minute version you talk through on a call. This is the
silent 90-second version you put in a cold email, where nobody has agreed to
give you 30 minutes yet.

The two differ in one way that changes every decision below: **nobody will hear
it.** Email and LinkedIn autoplay muted, and most people never turn sound on. So
the narration has to be visible, and the fastest way to make it visible is to
put it in the terminal rather than in a video editor.

## What to record with

| | |
|---|---|
| **Loom desktop app** | Records and hosts in one step, gives you a link with a thumbnail, and tells you who watched. Start here. |
| Windows Game Bar (`Win+G`) | Built in, zero install, records the active window. Fine if you would rather not sign up for anything. |
| OBS Studio | Free, best quality, records a fixed region. Worth it for the second version, not the first. |

Host it on Loom and paste the link. Do not attach a video file to a cold email,
and do not use a GIF — terminal text dithers badly and the file will be huge.

## Setup, once

**Run Postgres locally, not on Neon.** Every command in the demo makes a
database round trip, and over six commands a remote database adds ten to
fifteen seconds of dead air to a ninety-second video. Local is instant:

```powershell
docker run -d --name lethe-demo -e POSTGRES_PASSWORD=demo -p 5432:5432 pgvector/pgvector:pg16
$env:DEMO_DATABASE_URL = "postgresql://postgres:demo@localhost:5432/postgres"
```

The image must be `pgvector/pgvector` — `setup.py` runs `CREATE EXTENSION
vector` and searches with `<->`, so stock `postgres` will not do.

Then the usual seed, which also prints the public key you will need:

```powershell
& "$repo\examples\recruiting-demo\start-demo.ps1"
```

**Before you hit record:**

- Terminal font at **20pt or larger**. People watch this in a mail client, in a
  window a third of their screen. Anything smaller is unreadable and they stop.
- Shorten the prompt so it is not a long path — `function prompt { "> " }`.
- Window at 1280×720 or 1600×900. Not fullscreen on a 4K monitor.
- Browser: hide the bookmarks bar, zoom to 125–150%, one tab.
- **Paste the public key into the verifier now**, before recording. It is the
  operator's *published* key — it legitimately lives in your verifier tab, and
  pasting two different things from one clipboard on camera is fifteen wasted
  seconds.
- Turn on Focus Assist. A Slack notification lands in the middle of the take
  every single time.
- Do one full dry run. The take after a dry run is always the one you keep.

## The captions trick

Do not open a video editor. Type the narration as a comment line immediately
before each command:

```powershell
# A live vector index. Alice Chen is in it.
python search.py "senior React engineer in Berlin, fintech"
```

It reads naturally in a terminal, costs no editing, and it is legible at small
sizes because it is the same big monospace font as everything else. The browser
half needs no captions at all — VALID and INVALID say it themselves.

## Shot list

Total 85 seconds. Times are where each beat *starts*.

| | At | On screen | The line |
|---|---|---|---|
| 1 | 0:00 | Title card, or just an empty terminal | `# Can you delete one person from your AI's memory?` |
| 2 | 0:06 | `python search.py "senior React engineer in Berlin, fintech"` | `# A live vector index. Alice Chen is in it.` |
| 3 | 0:18 | `python forget.py alice.chen@demo.test` | `# Alice asks to be forgotten. One call.` |
| 4 | 0:26 | The same search again — Alice gone, Bob and Carol untouched | `# Gone from search. The embedding is deleted, not hidden.` |
| 5 | 0:38 | `type cert.json` | `# And a signed certificate of exactly what was removed.` |
| 6 | 0:50 | Verifier: paste the certificate, click Verify → **VALID** | *(none — the four PASS rows carry it)* |
| 7 | 1:05 | Change `records_deleted` from 1 to 2, click Verify → **INVALID** | *(none — "the payload has been altered" is on screen)* |
| 8 | 1:18 | End card: your name, your email, the repo link | |

Beat 4 is the one the whole video exists for. Let it sit on screen a beat
longer than feels comfortable — that is the moment someone realises a `DELETE`
on the row would not have done this.

Beat 7 is what makes beat 6 mean anything. A certificate that always says VALID
is a picture of a certificate.

## What goes wrong

- **Dead air.** The single biggest problem. Local Postgres fixes most of it; trim
  the rest in Loom, or speed the whole thing to 1.25×.
- **Recording the whole desktop.** Record the window or a region. Your other
  monitors, your taskbar and your unread badges are not part of the pitch.
- **Loading the built-in example instead of your own certificate.** The
  verifier's "Load example" button holds a different, synthetic certificate for
  checking the page works. In the video, paste the real `cert.json` that
  `forget.py` just wrote.
- **Re-recording to fix one word.** Do not. Nobody watching a ninety-second
  terminal demo is grading your typing.

## Reset between takes

```powershell
python setup.py
```

Re-seeds Alice, Bob and Carol, and reuses the existing key — so the public key
already sitting in your verifier tab stays correct across takes.
