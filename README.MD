# Studio66 TV

### BASH script to automate recordings of normal TV webstreams from [Studio66 TV](https://studio66tv.com)

---

Created for personal use only. No implied guarantee this works. Use at your own risk.
Created and tested on [Debian Buster](https://wiki.debian.org/DebianBuster), but should work on any reasonably current Linux OS, so long as BASH is v4 or higher and external programs are installed.

---

Script automates recordings.
Uses two parameters passed when executed.
* channel number (must be a digit, is usually 1 to 4 to match that they run 4 streams on website)
* show type (must be either DayShow or NightShow). This affects the duration, and also by default the filename

Note that whilst there are 4 streams on the website, they do not automatically align to channels 1 to 4.
There are only 3 channels on satellite.
Web streams are numbered based on the channelID used by the streaming servers and the stream provider.

By way of example, during daytime the streams and channelIDs are
* stream 1 is channelID 345
* stream 2 is channelID 341
* stream 3 is channelID 343
* stream 4 is channelID 347

At night, there is normally no stream 2. There are duplicate channelIDs for stream 3 depending on what type of show is on.
So at night, it could be defined as a combination of
* stream 1 is channelID 345 (matching daytime)
* stream 2 is not defined. If it is used, then it also matches daytime and hence channelID of 341
* stream 3 is either channelID 2639 (most commonly) or 2701
* stream 4 is either channelID 963 (most commonly) or 6562 (very rarely)

---

Uses external functions of
* [streamlink](https://streamlink.github.io/) for actual stream recording
* [jq](https://stedolan.github.io/jq/) for reading and processing of json

---

`ini` file needs to be adjusted to your own preferences for some variables.
Also if you wish to record without stream timeout, i.e. logged on, you will need to adjust 2 lines in `ini` file.
* *opt_username* is login name of your account. i.e. what you use as part of login page on main website.
* *opt_session_key* is your unique key, which is set and lasts for 365 days (I believe). It should be 31 characters long.

Getting the values of these 2 items is not difficult, by making use of view-source in your browser and the URLs used from the website, when you log in. 
So long as you enter these correctly, the script will automatically obtain your `ccivrid` and `session-key` to support recording as if logged on (i.e. no stream timeout).
It will update the `ini` file with these values, and not try and get them for subseqeunt runs.

---

### TO DO
1. ~~Adjust json processing to be more script based - currently everything is hard coded, and overly complex~~ (Done in v2)
2. Identify if channelID of 2727 for Daytime Xtra will be used, and if so what stream number it would map to.

