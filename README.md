# Whatsapp to Telegram - Redirect

Simple tool that redirects whatsapp messages to telegram.
Based on https://github.com/shashwat001/whatsapp-web-graph. Updated the code so that now it works. Removed unnecessary logging and data collection.

To make it work edit the variables:
- telegramToken
- telegramChatId
In the first run a `qrcode.png` file will be created and delivered to the telegram chat. Use `Whatsapp` > `Linked Devices` >`Link a device` and scan the qrcode.  