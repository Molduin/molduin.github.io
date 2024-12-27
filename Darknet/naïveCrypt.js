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

// Encrypting utilities
function encryptAndDownloadFile(useHash){
    const files = document.getElementById("fileInput").files;
    if(files.length == 0) return;
    const file = files[0];
    const reader = new FileReader();
    reader.readAsArrayBuffer(file);
    reader.addEventListener("loadend", () => {
        const pwd = document.getElementById("filePassword").value;
        if(pwd == "" || pwd == null) {
            console.log("Encrypting failed. You must provide a password.")
            alert("Encrypting failed. You must provide a password.");
            return;
        }
        const data = new Uint8Array(reader.result);
        const encryptedData = encrypt(data, pwd);
        if(useHash){
            const passHash = toHexString(defaultHash(assertUint8Array(pwd)));
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

// Decrypting utilities
async function findAndLoad(password) {
    password = assertUint8Array(password);
    const passHash = toHexString(defaultHash(password));
    const filePath = "Files/"+passHash;
    console.log("filePath: "+filePath);
    if(!await fileExists(filePath)){
        alert("Incorrect password!");
        return;
    }
    const content = await readFile(filePath, password);
    // Content is not supposed to include <!DOCTYPE html> and <html></html>.
    document.querySelector("html").innerHTML
        = //"<head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'><title>" + // </title></head>
        new TextDecoder("UTF-8").decode(content);
}

async function readFile(path, key) {
    const string = await fetchFile(path);
    const decrypted = encrypt(string, key);
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

/**
 * 
 * @param {(string|Uint8Array)} text - Text to be encrypted
 * @param {(string|Uint8Array)} key - Encryption key or password
 */
function encrypt(text, key) {
    text = assertUint8Array(text);
    key = assertUint8Array(key);

    /*  Extra security measure so you don't have to change the password when editing a file in case its length has changed
        (which it probably has if you have made any substantial edits).
        This way, we avoid encrypting two different blocks of plaintext (the original one, and the changed one)
        using the same part of the overlay. */
    key = [...key, ...numToUint8Array(text.length)];

    // Might be larger than the text if the size of the text is not a multiple of 512 bits (64 bytes)
    let overlay = streamA(Math.ceil(text.length/64), key);
    let ciphertext = xor(text, overlay, text.length);

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
     * Arguments have to be of the same length, or no more than numOfBytes
     * @param {Uint8Array} array1 
     * @param {Uint8Array} array2 
     * @param {number} numOfBytes - The amount of bytes in the result. Must be at most the length of either array1 or array2, whichever one is smaller.
     */
    function xor(array1, array2, numOfBytes){

        let result = new Uint8Array(numOfBytes);
        for(let i = 0; i < numOfBytes; i++){
            result[i] = array1[i]^array2[i];
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

function numToUint8Array(num) {
    let arr = new Uint8Array(8);
  
    for (let i = 0; i < 8; i++) {
      arr[i] = num % 256;
      num = Math.floor(num / 256);
    }
  
    return arr;
}