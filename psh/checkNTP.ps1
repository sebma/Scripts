# Source - https://stackoverflow.com/a/79389976
# Posted by curx
# Retrieved 2026-06-16, License - CC BY-SA 4.0

$ntpservercheck = w32tm /query /status | Select-String -Pattern '^Source:'
$ntpserver = $ntpservercheck.ToString().Replace('Source:', '').Trim()
w32tm /stripchart /computer:$ntpserver /dataonly /samples:5
