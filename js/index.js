const myWorker = new Worker('js/worker.js');

let sendToWorker = false;
function GetRandomSalt()
{
	var randomBytes = new Uint8Array(12);
	
	for (let i = 0; i < randomBytes.length; i++) 
	{
		randomBytes[i] = (Math.random()*255) >> 0	
	}
	return randomBytes.reduce((previous, currentValue) => {return previous + currentValue.toString(16)});
}

function GeneratePasswordOnWorker(password, salt, mode)
{
	myWorker.postMessage({
		functionCall: GENERATE_PASSWORD,
		args: {
			password,
			salt,
			mode
		}
	});	
}

function EncryptPasswordOnWorker(password, field)
{
	myWorker.postMessage({
		functionCall: ENCRYPT_DATA,
		args: {
			password,
			field
		}
	});	
}

function DecryptPasswordOnWorker(password, field)
{
	myWorker.postMessage({
		functionCall: DECRYPT_DATA,
		args: {
			password,
			field
		}
	});	
}

function OnPasswordChange()
{
	if (false == sendToWorker)
		return;

	let mode = document.getElementById("EncryptionMode").value * 1;
	let saltField = document.getElementById("SaltField");
	let randomize = document.getElementById("SaltRandomizeField").checked;
	if(randomize === true && mode == ENCRYPTION_MODE_PBKDF2)
	{
		saltField.value = GetRandomSalt();
	}
	let salt = saltField.value;
	let password = document.getElementById("PasswordField").value;
	GeneratePasswordOnWorker(password, salt, mode);
	//console.log("Calling worker")

}

function OnRandomizeFieldChange()
{
	let mode = document.getElementById("EncryptionMode").value * 1;
	if(mode != ENCRYPTION_MODE_PBKDF2)
		return;
	let randomizeField = document.getElementById("SaltRandomizeField");
	let salt = document.getElementById("SaltField");
	if (randomizeField.checked === true)
	{
		salt.classList.add("no-input");
		salt.disabled = true;
		OnPasswordChange();
	}
	else
	{
		salt.classList.remove("no-input");
		salt.disabled = false;
	}
}

function EncryptionModeChange()
{
	let mode = document.getElementById("EncryptionMode").value * 1;
	let salt = document.getElementById("SaltField");
	let randomizeField = document.getElementById("SaltRandomizeField");
	switch(mode)
	{
		case ENCRYPTION_MODE_MD5:
			randomizeField.disabled = true
			salt.disabled = true;
			salt.classList.add('disabled');
			salt.classList.remove("no-input");
			salt.value = "";
			break;
		case ENCRYPTION_MODE_SHA2_MD5:
			randomizeField.disabled = true
			salt.disabled = true;
			salt.classList.add('disabled');
			salt.classList.remove("no-input");
			salt.value = "";
			break;
		case ENCRYPTION_MODE_PBKDF2:
			salt.disabled = false;
			salt.classList.remove('disabled');
			randomizeField.disabled = false;
			if (randomizeField.checked === true)
			{
				salt.classList.add("no-input");
				salt.disabled = true;
				if (salt.value == "")
					salt.value = GetRandomSalt();
			}
			break;
	}
	//OnPasswordChange();
	GeneratePasswordOnWorker(document.getElementById("PasswordField").value, salt.value, mode);
}

function OnEncryptResultClick()
{
	let encryptResultField = document.getElementById("EncryptResultField");
	let resultField = document.getElementById("ResultField");
	let mode = document.getElementById("EncryptionMode").value * 1;
	let salt = document.getElementById("SaltField");
	if(encryptResultField.checked == true)
	{
		EncryptPasswordOnWorker(resultField.value, "ResultField");
	}
	else
	{
		GeneratePasswordOnWorker(document.getElementById("PasswordField").value, salt.value, mode);
	}
}

function OnCipherInputChange()
{
	const CipherInputField 		= document.getElementById("CipherInputField").value;
	const CipherFunctionField 	= document.getElementById("CipherFunctionField").value - 1;
	if(CipherFunctionField == DECRYPT_DATA)
	{
		DecryptPasswordOnWorker(he.decode(CipherInputField.trim()), "CipherResultField");
		//_.unescape("$2QRTqKHqFz&lt;}*+cVC#oI,5~081XX~w5\\T*cPo5IY&amp;TO+q0_1;p!u.[&amp;AV$ki5$")
	}
	else
	{
		EncryptPasswordOnWorker(CipherInputField, "CipherResultField");
	}
}


myWorker.addEventListener('message', (e) => {
	let encryptResultField = document.getElementById("EncryptResultField");
	let resultField = document.getElementById("ResultField");
	switch(e.data.functionCall)
	{
		case GENERATE_PASSWORD:
			if(encryptResultField.checked == true)
			{
				EncryptPasswordOnWorker(e.data.return, "ResultField");
			}
			else
			{
				resultField.value = e.data.return;
			}
			break;
		case DECRYPT_DATA:
		case ENCRYPT_DATA:
			let field = document.getElementById(e.data.field);
			field.value = e.data.return;
			
			break;
	}
});

EncryptionModeChange();
OnRandomizeFieldChange();
sendToWorker = true;
GeneratePasswordOnWorker(document.getElementById("PasswordField").value, 
						document.getElementById("SaltField").value, 
						document.getElementById("EncryptionMode").value * 1);
OnCipherInputChange();

const pages = ["home", "passgen", "cipher"]

function popStateEvent(e)
{
	let target = document.location.hash.substr(1); 
	if(target == "")
		target = "home"
	const elem = document.getElementById(target);
	if(elem == null)
		return;

	pages.forEach(page => {
		if(page == target)
		{
			elem.style.display = "block";
			document.getElementById(page + "link").classList.add("active-page")
		}
		else
		{
			document.getElementById(page + "link").classList.remove("active-page")
			document.getElementById(page).style.display = "none";
		}

	})

}

window.addEventListener('popstate', popStateEvent);
popStateEvent();