# AIVE demo — recorded with vhs (https://github.com/charmbracelet/vhs)
Output docs/media/demo.gif

Set Shell "bash"
Set FontSize 15
Set Width 1240
Set Height 720
Set Padding 18
Set Theme "Catppuccin Mocha"
Set TypingSpeed 30ms

Hide
Type "source .venv/bin/activate && clear" Enter
Sleep 400ms
Show

Type "# AIVE — an exploit-to-patch loop for the age of AI red teams" Sleep 700ms Enter
Sleep 500ms
Type "aive --version" Sleep 400ms Enter
Sleep 1s

Type "# 1. Scan a repo. Fast triage view, worst-first:" Sleep 600ms Enter
Type "aive scan /tmp/aive-demo-target --format compact" Sleep 400ms Enter
Sleep 2.5s

Type "# 2. Same scan, painted for humans (rich, optional):" Sleep 600ms Enter
Type "aive scan /tmp/aive-demo-target --pretty" Sleep 400ms Enter
Sleep 3s

Type "# 3. Turn findings into a safe, staged patch plan:" Sleep 600ms Enter
Type "aive scan /tmp/aive-demo-target --output /tmp/f.json >/dev/null && aive plan /tmp/f.json | head -18" Sleep 400ms Enter
Sleep 3s

Type "# 4. Gate a PR on NEW risk only — diff against a baseline:" Sleep 600ms Enter
Type "aive diff /tmp/aive-demo-target --baseline /tmp/f.json --markdown | head -12" Sleep 400ms Enter
Sleep 3s

Type "# 5. Verify the repo is loop-ready:" Sleep 600ms Enter
Type "aive verify . --pretty" Sleep 400ms Enter
Sleep 3s

Type "# main stays human-owned. AI patches in a constrained lane. ✦" Sleep 800ms Enter
Sleep 2s
