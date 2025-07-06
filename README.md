# Setup
- Copy `<script src="https://raw.githubusercontent.com/jeb1399/simple-VPN-detector/refs/heads/main/detector.js"></script>` into the bottom of your `<body>` section of your website just before `</body>`

# Additional settings
- **Change the popup window:**
. In order to change the popup menu just create a new `<script></script>` tag underneath the one that imports the detector then copy and paste `window.vpndetector.changePopup.innerHTML` into it after set it to your own html content by adding ` = "<p>your content</p>"` so the full thing should look something like this `<script>window.vpndetector.changePopup.innerHTML = "example content";</script>` the countdown will stay you dont need to add any additional code to add it back in.
