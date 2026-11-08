# Records the real Rin and Guardrail runs for the demo video.
#   brew install vhs
#   aws sso login --profile vorrin-admin
#   vhs docs/demo/rin-terminal.tape
# Run from the repository root. Output: build/demo/rin-terminal.mp4
# The commands call Claude Haiku on Bedrock and the published Guardrail
# (a few cents). Neither prints an account ID or ARN.

Output build/demo/rin-terminal.mp4
Set Shell "bash"
Set FontSize 18
Set Width 1920
Set Height 1080
Set Padding 40
Set Theme "Dracula"
Set TypingSpeed 35ms
Set WindowBar Colorful

Hide
Type "source .venv/bin/activate && export PS1='vorrin $ ' && clear"
Enter
Sleep 1s
Show

Type "# Rin's Bedrock Guardrail: 26 attack and must-allow cases"
Enter
Sleep 1s
Type "python3 scripts/phase3_rin_guardrail.py evaluate --profile vorrin-admin --version 3"
Enter
Sleep 35s
Sleep 4s

Type "clear"
Enter
Type "# Rin end to end: Claude Haiku on Amazon Bedrock + the published Guardrail"
Enter
Sleep 1s
Type "python3 scripts/phase3_rin_evaluation.py --profile vorrin-admin --model us.anthropic.claude-haiku-4-5-20251001-v1:0 --guardrail-version 3"
Enter
Sleep 75s
Sleep 6s
