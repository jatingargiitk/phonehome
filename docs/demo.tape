# Recorded with vhs: vhs docs/demo.tape
Output docs/demo.gif
Set Shell bash
Set FontSize 15
Set Width 1180
Set Height 720
Set Padding 16
Set TypingSpeed 35ms
Set Theme "Builtin Dark"

Hide
Type "export PS1='$ ' HF_HOME=/tmp/hfdemo && alias phonehome='node bin/phonehome.js' && clear"
Enter
Show

Type "phonehome -- node examples/no-network.js"
Enter
Sleep 2.5s
Type "phonehome -- node examples/egress-demo.js; echo exit=$?"
Enter
Sleep 4.5s
Type "clear"
Enter
Type "phonehome --opt-out-env -- hf download openai-community/gpt2 config.json"
Enter
Sleep 5s
Type "clear"
Enter
Type "phonehome scan examples/remote-code-model"
Enter
Sleep 4.5s
