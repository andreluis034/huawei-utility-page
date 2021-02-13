const BLOCK_SIZE = 0X14;
importScripts("constants.js", 
	"https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.0.0/crypto-js.min.js", 
	"https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.0.0/enc-hex.min.js");

Uint8Array.prototype.readUInt32LE = function(offset)
{
	var output = new Uint32Array([0])
	for (let i = 3; i >= 0; i--) 
	{
		output[0] = output[0] << 8;
		output[0] |= this[offset + i];
	}

	return output[0];
}

Uint8Array.prototype.writeUInt32LE = function(value, offset)
{
	for (let i = 0; i < 4; i++) 
	{
		this[offset + i] = value & 0xFF;	
		value = value >> 8;
	}
}

/**
 * Decodes to a buffer the encoded string
 * @param {String} encryptedStr 
 * @returns {Uint8Array}
 */
function HW_AES_AscUnvisible(encryptedStr)
{
	let buf = new Uint8Array(encryptedStr.split('').map(c => c.charCodeAt(0)));
	for (let i = 0; i < buf.length; i++) {
		if (0x7e == buf[i]) // character ~
			buf[i] = 0x1e;
		else
			buf[i] = buf[i] - 0x21; // chracter !
	}
	return buf;
}

/**
 * Encodes the buffer to an ascii string 
 * @param {Buffer} buffer
 * @returns {String} 
 */
function HW_AES_AscVisible(buffer)
{
	let outputEncoded = ""
	for (let i = 0; i < buffer.length; i++) 
	{
		let encodedChar = buffer[i];
		if (encodedChar == 0x1E) 
			encodedChar = 0x7e // char ~
		else
			encodedChar += 0x21;

		outputEncoded += String.fromCharCode(encodedChar);
	}
	return outputEncoded
}

/**
 * 
 * @param {Buffer} buffer 
 * @returns {Number}
 */
function HW_AES_AesEnhSysToLong(buffer)
{
	let output = 0;
	let v3 = 1;
	for (let i = 0; i < 5; i++) 
	{
		output += v3 * buffer[i];
		v3 *= 0x5D;
	}
	return output;
}

/**
 * 
 * @param {Number} number 
 * @returns {Buffer}
 */
function HW_AES_LongToAesEnhSys(number)
{
	let outputBuffer = new Uint8Array(5);// Buffer.alloc(5);
	let i = 0;
	do
	{
		let remainder = number % 0x5D;
		number = (number / 0x5D) >> 0; //integer division
		outputBuffer[i] = remainder;
		i++;
	}while(number > 0);

	return outputBuffer;

}

/**
 * 
 * @param {Uint8Array} buffer of multiple of 5, from encoded data
 * @returns {Uint8Array} Binary data array to be processed by AES
 */
function HW_AES_PlainToBin(buffer)
{	
	if (buffer.length % 5 != 0)
		return;

	let output = new Uint8Array(buffer.length * 4/5);// Buffer.alloc(buffer.length * 4/5);
	let periodFive = 0;
	for (let i = 0; i != output.length; i += 4) 
	{
		let _long =  HW_AES_AesEnhSysToLong(buffer.slice(periodFive, periodFive + 5));
		output.writeUInt32LE(_long, i);
		periodFive += 5;
	}
	return output;
}

/**
 * 
 * @param {Uint8Array} buffer of size multiple of 4, from encrypted data
 * @returns {Uint8Array} Binary data array to be encoded to a string
 */
function HW_AES_BinToPlain(buffer)
{
	if (buffer.length % 4 != 0)
		return;
	let output = new Uint8Array(buffer.length * 5 /4);// Buffer.alloc(buffer.length * 5/4);

	let periodFive = 0;
	for (let i = 0; i != buffer.length; i += 4) 
	{
		let longPlain = HW_AES_LongToAesEnhSys(buffer.readUInt32LE(i));
		for (let j = 0; j < longPlain.length; j++) 
		{
			output[periodFive + j] = longPlain[j];
		}
		periodFive += 5;
	}
	return output;
}

/**
 * Checks if it conforms with huawei's encrypted string 
 * @param {String} encryptedStr 
 * @returns {String}
 */
function HW_AES_Trim(encryptedStr)
{
	if(encryptedStr.length < 3)
		return "";
	if("$" != encryptedStr[0] || "2" != encryptedStr[1] || "$" != encryptedStr[encryptedStr.length - 1])
	{
		return "";
	}
	return encryptedStr.substr(2, encryptedStr.length - 3);
}

/**
 * Decrypts a string encrypted and encoded by an Huawei router
 * @param {String} input The input string, it must start with $2 and end with $
 * @param {String | Uint8Array} key used to decrypt, if a string is provided it will be interpreted as HEX data and converted to a buffer
 * @returns {String} the decrypted data as an utf8 string
 */
function HW_AESCBC_Decrypt(input, key)
{
	if (!input instanceof Uint8Array && typeof input != "string")
		return "";
	if (!key instanceof Uint8Array && typeof key != "string")
		return "";
	if (key instanceof Uint8Array)
		key = toHexString(key);


	let decrypted = "";
	let unvisible = HW_AES_AscUnvisible(HW_AES_Trim(input));
	let blockCount = (unvisible.length / BLOCK_SIZE) >> 0;
	if (unvisible.length != BLOCK_SIZE * blockCount)
		return "";


	let IV = Global_IV = HW_AES_PlainToBin(unvisible.slice(blockCount * BLOCK_SIZE - BLOCK_SIZE, blockCount * BLOCK_SIZE ));
	const dataAll = HW_AES_PlainToBin(unvisible.slice(0, blockCount * BLOCK_SIZE - BLOCK_SIZE));

	let result = CryptoJS.AES.decrypt(toHexString(dataAll), CryptoJS.enc.Hex.parse(key), {
		iv:	CryptoJS.enc.Hex.parse(toHexString(IV)),
		mode: CryptoJS.mode.CBC,
		format: CryptoJS.format.Hex
	});
	result.sigBytes = dataAll.length; //Force to allow, Bug in JSCrypt?

	return result.toString(CryptoJS.enc.Utf8)
	
}

const fromHexString = hexString =>
  new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

const toHexString = bytes =>
  bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), ''); 
/**
 * 
 * @param {String} data to encrypt
 * @param {String | Uint8Array} key used to encrypt, if a string is provided it will be interpreted as HEX data
 * @param {String | Uint8Array} IV used to encrypt, if a string is provided it will be interpreted as HEX data
 * @returns {String} Huawei encoded output
 */
function HW_AESCBC_Encrypt(data, key, IV)
{
	if (!data instanceof Uint8Array && typeof data != "string")
		return "";
	if (!key instanceof Uint8Array && typeof key != "string")
		return "";
	if (!IV instanceof Uint8Array && typeof IV != "string")
		return "";
	if (key instanceof Uint8Array)
		key = toHexString(key);
	if (IV instanceof Uint8Array)
		IV = toHexString(IV);
	//console.log(`HW_AESCBC_Encrypt("${data}", "${key}", "${IV}")`)
	
	let result = CryptoJS.AES.encrypt(data, CryptoJS.enc.Hex.parse(key), {
		iv:	CryptoJS.enc.Hex.parse(IV),
		mode: CryptoJS.mode.CBC,
		format: CryptoJS.format.Hex,
		padding: CryptoJS.pad.ZeroPadding
	});
	let hexEncrypted = result.toString();
	let binaryData = new Uint8Array(hexEncrypted.length / 2 + IV.length/2); // Buffer.alloc(hexEncrypted.length / 2 + IV.length);//  Buffer.from(result.toString(), "hex");
	binaryData.set(fromHexString(hexEncrypted), 0);
	binaryData.set(fromHexString(IV), hexEncrypted.length / 2);
	return `$2${HW_AES_AscVisible(HW_AES_BinToPlain(binaryData))}$`;
}

/**
 * Hashes the given password
 * @param {String} password the password to hash
 * @param {String} salt used with the password, only valid for mode = ENCRYPTION_MODE_PBKDF2
 * @param {Number} mode utilized to hash the password
 */
function GeneratePassword(password, salt, mode)
{
	switch(mode)
	{
		case ENCRYPTION_MODE_MD5:
			return CryptoJS.MD5(password).toString(CryptoJS.enc.Hex);
		case ENCRYPTION_MODE_SHA2_MD5:
			return CryptoJS.SHA256(CryptoJS.MD5(password).toString(CryptoJS.enc.Hex)).toString(CryptoJS.enc.Hex);
		case ENCRYPTION_MODE_PBKDF2:
			return CryptoJS.PBKDF2(password, salt, {
				keySize: 256 / 32,
				hasher: CryptoJS.algo.SHA256,
				iterations: 5000
			}).toString(CryptoJS.enc.Hex);
	}
	return "";
}

/**
 * 
 * @param {Number} size	the size of the array to generate
 * @returns {Uint8Array} array of random data 
 */
function GetRandomByteArray(size)
{
	var randomBytes = new Uint8Array(size);
	
	for (let i = 0; i < randomBytes.length; i++) 
	{
		randomBytes[i] = (Math.random()*255) >> 0	
	}
	return randomBytes;// randomBytes.reduce((previous, currentValue) => {return previous + currentValue.toString(16)});
}

onmessage = function(e) 
{
	if(e == null || e.data == null || e.data.functionCall == null)
		return;
	let returnedData = {
		functionCall: e.data.functionCall,
		return: null
	}
	switch(e.data.functionCall)
	{
		case GENERATE_PASSWORD:
			returnedData.return = GeneratePassword(e.data.args.password, e.data.args.salt, e.data.args.mode);
			break;
		case ENCRYPT_DATA:
			returnedData.return = HW_AESCBC_Encrypt(e.data.args.password, PASSWORD_HEX, GetRandomByteArray(0x10));
			returnedData.field = e.data.args.field;
			break;
		case DECRYPT_DATA:
			returnedData.return = HW_AESCBC_Decrypt(e.data.args.password, PASSWORD_HEX);// HW_AESCBC_Encrypt(e.data.args.password, PASSWORD_HEX, GetRandomByteArray(0x10));
			returnedData.field = e.data.args.field;
			break;
	}
	postMessage(returnedData);
}




//console.log(HW_AESCBC_Decrypt(_.unescape("$2QRTqKHqFz&lt;}*+cVC#oI,5~081XX~w5\\T*cPo5IY&amp;TO+q0_1;p!u.[&amp;AV$ki5$"), PASSWORD_HEX));