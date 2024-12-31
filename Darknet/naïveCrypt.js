/**
 * Using any of the algorithms implemented here is discouraged.
 * Even though they are *probably* secure (if you know what you are doing),
 * they are intended for learning purposes only, and are probably ridiculously inefficient.
 * I do not have any formal education in the field of cryptography.
 * 
 * That said, I still trust this algorithm enough to potentially hide some stuff behind it.
 */

const typeSizes = {
    "undefined": () => 0,
    "boolean": () => 4,
    "number": () => 8,
    "string": item => 2 * item.length,
    "object": item => !item ? 0 : Object
      .keys(item)
      .reduce((total, key) => sizeOf(key) + sizeOf(item[key]) + total, 0)
  };
  
const sizeOf = value => typeSizes[typeof value](value);

// ENCRYPTING UTILITIES
function encryptAndDownloadFile(files, domain, password, useFileName, useHash, removeBodyTag, decrypt){
    // Input handling

    if(files.length == 0) {
        alert("No files provided.");
        return;
    }
    const file = files[0];
    const fullPwd = useFileName ? file.name : domainConcat(domain, password);
    if(fullPwd == "" || fullPwd == null) {
        console.log("Encrypting failed. You must provide a password.")
        alert("Encrypting failed. You must provide a password.");
        return;
    }
    _encryptAndDownloadFile(file, fullPwd, useHash, removeBodyTag, decrypt);
}

function _encryptAndDownloadFile(file, password, useHash, removeBodyTag, decrypt){
    const reader = new FileReader();
    reader.readAsArrayBuffer(file);
    reader.addEventListener("loadend", () => {
        const data = new Uint8Array(reader.result);
        const encryptedData = removeBodyTag ?
            encrypt(data, password, 22, 8, decrypt) : encrypt(data, password, 0, 0, decrypt);
        if(useHash){
            const passHash = toHexString(defaultHash(assertUint8Array(password)));
            downloadFile(passHash, encryptedData);
        } else {
            const name = file.name.toString();
            if(name.lastIndexOf("ENCRYPTED_",0)===0) {
                var encryptedFileName = name.substr(10); // Mhh I love var scoping
            } else {
                var encryptedFileName = "ENCRYPTED_" + file.name.toString();
            }
            downloadFile(encryptedFileName, encryptedData);
        }
    })
}

function downloadFile(name, data) {
    let a = document.createElement("a");
    if (typeof a.download !== "undefined") a.download = name;
    a.href = URL.createObjectURL(new Blob([data], {
        type: "octet/stream"
    }));
    a.dispatchEvent(new MouseEvent("click"));
}

// DECRYPTING UTILITIES

async function findAndLoad(password, useDomain) {
    if (useDomain == true)
        password = prependDomainIfExists(password);
    password = assertUint8Array(password);
    const passHash = toHexString(defaultHash(password));
    const filePath = "Files/"+passHash;
    console.log("filePath: "+filePath);
    if(!await fileExists(filePath)){
        alert("Incorrect password!");
        return;
    }
    const content = await readFile(filePath, password);
    // Content doesn't need to include <!DOCTYPE html> and <html></html>. However, it won't break most browsers if it does.
    document.querySelector("html").innerHTML = new TextDecoder("UTF-8").decode(content);
}

function prependDomainIfExists(password) {
    const domainElement = document.getElementById('domain');
    if (domainElement == null) return password;
    return domainConcat(domainElement.innerText, password);
}

function domainConcat(domain, password){
    if (domain === "" || domain == null || domain == undefined) return password;
    if (password === "" || password == null || password == undefined) return domain;
    return domain + "/" + password;
}

async function readFile(path, key) {
    const string = await fetchFile(path);
    const decrypted = encrypt(string, key, 0, 0, true)
    return decrypted;
}

async function fetchFile(filename) {
    const response = await fetch(filename);
    if (!response.ok) throw new Error('Failed to fetch '+filename);
    var buf = await response.arrayBuffer();
    return new Uint8Array(buf); // OK
}

async function fileExists(path) {
    try {
        const response = await fetch(path, { method: 'HEAD' });
        return response.ok;
    } catch (err) {
        console.error('An error occurred:', err);
        return false;
    }
}

function decrypt(text, key) {
    return encrypt(text, key, 0, 0, true);
}

/**
 * @param {(string|Uint8Array)} text - Text to be encrypted
 * @param {(string|Uint8Array)} key - Encryption key or password
 * @param {num} startMargin - Number of bytes at the start of the data that are discarded
 * @param {num} endMargin - Number of bytes at the end of the data that are discarded
 * @param {bool} decrypt - Mode. If true, decrypts. If false, encrypts.
 */
function encrypt(text, key, startMargin, endMargin, decrypt) {
    text = assertUint8Array(text);
    key = assertUint8Array(key);

    let salt = new Uint8Array(8);
    if(decrypt){ // First 8 bits of any encrypted data are its salt
        for(var i = 0; i < 8; i++) {
            salt[i] = text[i];
        }
        startMargin += 8;
    } else { // Add random salt so you can re-use the same key after changing a file. Size is 8 bytes
        salt = window.crypto.getRandomValues(salt);
    }
    key = [...key, ...salt];

    // Might be larger than the text if the size of the text is not a multiple of 512 bits (64 bytes)
    let overlay = streamA(Math.ceil((text.length-startMargin-endMargin)/64), key);
    let ciphertext = xor(text, overlay, text.length-startMargin-endMargin, startMargin);

    if(!decrypt) { // If encrypting, prepend the salt
        return Uint8Array.from([...salt, ...ciphertext]);
    }
    return ciphertext;

    // ---------------------------------------------------------------------------------------------------------------

    function streamA(amountOfBlocks, key){
        let allBlocks = new Uint8Array();
        allBlocks = [...allBlocks];

        let currentBlock = new Uint8Array(64);
        for(let i = 0; i < amountOfBlocks; i++){
            currentBlock = generateBlock(currentBlock, key);
            allBlocks.push(...currentBlock);
        }

        function generateBlock(lastBlock, key) {
            return (new jsSHA("SHA-512", "UINT8ARRAY").update(lastBlock).update(key).getHash("UINT8ARRAY"));
        }

        return allBlocks;
    }

    /**
     * @param {Uint8Array} textArray - Use for data
     * @param {Uint8Array} overlayArray - Use for overlay
     * @param {number} numOfBytes - Amount of bytes in the result.
     * @param {number} startIndex - First byte of textArray to be considered.
     */
    function xor(textArray, overlayArray, numOfBytes, startIndex){

        let result = new Uint8Array(numOfBytes);
        for(let i = 0; i < numOfBytes; i++){
            result[i] = textArray[i+startIndex]^overlayArray[i];
        }

        return result;
    }
}

function assertUint8Array(stringOrArray){
    if(typeof stringOrArray === "string") stringOrArray = new TextEncoder().encode(stringOrArray);
    else if(!typeof stringOrArray === "UInt8Array") throw new Error();
    return stringOrArray;
}

/**
 * 
 * @param {Uint8Array} input 
 */
function defaultHash(input) {
    return multiHash(input, [2,1], 42)
}

// Used to quickly find the right file for a password
function multiHash(input, iterationArray, iterations) {
    let output = input;
    for(let i = 0; i < iterations; i++){
        let concatenate = false;
        for (let j = 0; j < iterationArray.length; j++) {
            for (let k = 0; k < iterationArray[j]; k++) {
                let shaObj = new jsSHA("SHA-512", "UINT8ARRAY");
                if (concatenate === true) output = [...output, ...input];
                output = shaObj.update(output).getHash("UINT8ARRAY");
            }
            concatenate = !concatenate;
        }
    }
    return output;
}

function toHexString(byteArray) {
    return Array.from(byteArray, function(byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('')
}

/**
 * @param {string} hexString 
 */
function fromHexString (hexString) {
    return Uint8Array.from(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
}