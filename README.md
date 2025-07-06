# Setup
Copy `<script src="https://github.com/jeb1399/simple-VPN-detector/detector.js"></script>` into the bottom of your `<body>` section of your website just before `</body>`

# Additional settings
  **Change the popup window: **
    In order to change the popup menu just create a new `<script></script>` tag underneath the one that imports the detector then copy and paste `window.vpndetector.changePopup.innerHTML` into it after set it to your own html content by adding ` = "<p>your content</p>"`.
