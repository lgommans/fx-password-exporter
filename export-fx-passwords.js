const fs = require('fs');
const sqlite3 = require('sqlite3');
const forge = require('node-forge');

function getLogins(profileDirectory, masterPassword) {
	const masterPasswordBytes = forge.util.encodeUtf8(masterPassword);
	const db = new sqlite3.Database(profileDirectory + '/key4.db');
	db.all('SELECT item1, item2 FROM metadata WHERE id = \'password\';', function(err, metaData) {
		if (err !== null) {
			console.log('Error running sql query 1.');
			process.exit(3);
		}

		const globalSalt = toByteString(metaData[0].item1.buffer);
		const item2 = toByteString(metaData[0].item2.buffer);
		const item2Asn1 = forge.asn1.fromDer(item2);
		const item2Salt = item2Asn1.value[0].value[1].value[0].value;
		const item2Data = item2Asn1.value[1].value;
		const item2Value = decryptKey(globalSalt, masterPasswordBytes, item2Salt, item2Data);
		if (item2Value && item2Value.data === 'password-check') {
			db.all('SELECT a11 FROM nssPrivate WHERE a11 IS NOT NULL;', function(err, nssData) {
				if (err != null) {
					console.log('Error running sql query 2.');
					process.exit(3);
				}

				const a11 = toByteString(nssData[0].a11.buffer);
				const a11Asn1 = forge.asn1.fromDer(a11);
				const a11Salt = a11Asn1.value[0].value[1].value[0].value;
				const a11Data = a11Asn1.value[1].value;
				const a11Value = decryptKey(globalSalt, masterPasswordBytes, a11Salt, a11Data);
				key = forge.util.createBuffer(a11Value).getBytes(24);

				const loginsFilePath = profileDirectory + '/logins.json';
				if (!fs.existsSync(loginsFilePath)) {
					throw new Error('logins.json was not found in this profile directory.');
				}

				const logins = [];
				const loginsData = fs.readFileSync(loginsFilePath, 'utf8');
				const profileLogins = JSON.parse(loginsData);
				for (const login of profileLogins.logins) {
					const decodedUsername = decodeLoginData(login.encryptedUsername);
					const decodedPassword = decodeLoginData(login.encryptedPassword);
					const username = decrypt(decodedUsername.data, decodedUsername.iv, key);
					const password = decrypt(decodedPassword.data, decodedPassword.iv, key);

					logins.push({
						hostname: login.hostname,
						username: username.data,
						password: password.data,
						timeCreated: login.timeCreated,
						timeLastUsed: login.timeLastUsed,
						timePasswordChanged: login.timePasswordChanged,
						timesUsed: login.timesUsed,
					});
				}

				// I tried console.log(JSOn.stringify(logins)), process.stdout.write(JSON.stringify(logins)), console.dir(logins), fs.writeFile(/dev/stdout, JSON.stringify(logins))
				// But javascript falis at all of them. So we have to bake JSOn manually and loop over each item. Let's hope you don't have an entry larger than 65535 bytes!
				console.log('[');
				var comma = '';
				for (var login in logins) {
					console.log(comma, JSON.stringify(logins[login]));
					comma = ',';
				}
				console.log(']');
			});
		} else {
			// TODO: Support key3.db?
			console.log('Master password incorrect.');
			process.exit(2);
		}
	});
}

function decodeLoginData(b64) {
	const asn1 = forge.asn1.fromDer(forge.util.decode64(b64));
	return {
		iv: asn1.value[1].value[1].value,
		data: asn1.value[2].value
	};
}

function decrypt(data, iv, key) {
	const decipher = forge.cipher.createDecipher('3DES-CBC', key);
	decipher.start({ iv: iv });
	decipher.update(forge.util.createBuffer(data));
	decipher.finish();
	return decipher.output;
}

function decryptKey(globalSalt, password, entrySalt, data) {
	const hp = sha1(globalSalt + password);
	const pes = toByteString(pad(toArray(entrySalt), 20).buffer);
	const chp = sha1(hp + entrySalt);
	const k1 = hmac(pes + entrySalt, chp);
	const tk = hmac(pes, chp);
	const k2 = hmac(tk + entrySalt, chp);
	const k = k1 + k2;
	const kBuffer = forge.util.createBuffer(k);
	const otherLength = kBuffer.length() - 32;
	const key = kBuffer.getBytes(24);
	kBuffer.getBytes(otherLength);
	const iv = kBuffer.getBytes(8);
	return decrypt(data, iv, key);
}

function pad(arr, length) {
	if (arr.length >= length) {
		return arr;
	}
	const padAmount = length - arr.length;
	const padArr = [];
	for (let i = 0; i < padAmount; i++) {
		padArr.push(0);
	}

	var newArr = new Uint8Array(padArr.length + arr.length);
	newArr.set(padArr, 0);
	newArr.set(arr, padArr.length);
	return newArr;
}

function sha1(data) {
	const md = forge.md.sha1.create();
	md.update(data, 'raw');
	return md.digest().data;
}

function hmac(data, key) {
	const hmac = forge.hmac.create();
	hmac.start('sha1', key);
	hmac.update(data, 'raw');
	return hmac.digest().data;
}

function toByteString(buffer) {
	return String.fromCharCode.apply(null, new Uint8Array(buffer));
}

function toArray(str) {
	const arr = new Uint8Array(str.length);
	for (let i = 0; i < str.length; i++) {
		arr[i] = str.charCodeAt(i);
	}
	return arr;
}

const args = process.argv.slice(2);

if (args.length != 1 || args[0] === '-h' || args[0] === '--help') {
	console.log("Please pass the profile directory as only argument, example:");
	console.log("~/.mozilla/firefox/34q98ujai.default/");
	console.log("Also note that your master password must be in masterpass.txt (in the\ncurrent working directory).");
	process.exit(1);
}

if (!fs.existsSync("masterpass.txt")) {
	console.log("masterpass.txt not found.");
	process.exit(2);
}

getLogins(args[0], fs.readFileSync("masterpass.txt", {encoding: 'utf-8'}).trim());

