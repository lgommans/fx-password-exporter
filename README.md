# Export Firefox Password Database

Dependencies: `sudo apt install nodejs node-sqlite3 node-node-forge`

Put your master password in `masterpassword.txt`

Now run the script and pass it your Firefox profile:

    nodejs export-fx-passwords.js ~/.mozilla/firefox/baew9iu.default/

It will print the results to stdout. Protip: piping the output to `jq` nicely
formats and syntax highlights it. I would use nodejs' built-in formatting and
highlighting using console.dir(), but that breaks after about 22KB of data.


## Credits

Based on https://github.com/kspearrin/ff-password-exporter/blob/master/src/renderer.js

Thanks a lot to Kyle Spearrin from Bitwarden for the hard work! I just adapted
it to avoid having to install npm or electron. Having to install hundreds of
nodejs packages from the repository is bad enough.

License is GPLv3, of course, because this is a derivative work (even if I
butchered it beyond recognition -- sorry about that).

