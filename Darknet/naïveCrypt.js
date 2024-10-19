/**
 * Using any of the algorithms implemented here is discouraged.
 * They are probably insecure and are intended for educational/learning purposes only.
 * I have little idea what I am doing.
 */

// import {jsSHA} from "./sha512";

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

let ciphertext = encrypt("Hello, world!","hunter2");
console.log(ciphertext); // Should be some byte salad
let decrypted = encrypt(ciphertext, "hunter2");
console.log(new TextDecoder().decode(decrypted)); // Should say "Hello, world!"

fetchFile("index.txt");
let array = defaultHash("hunter2");
console.log(array);
array = toHexString(array);
console.log(array);

async function findAndLoad(password) {
    const strings = (await fetchFile("index.txt")).split("\n");
    password = assertUint8Array(password);
    const passHash = defaultHash(password);
    for (let i = 0; i < strings.length; i++) {
        if (strings[i] === passHash) {
            document.body.innerHTML = await readFile(passHash, password)
            return;
        }
    }
    window.location.href = "404.html";
}

async function readFile(path, key) {
    const string = fetchFile(path);
    return encrypt(string, key);
}

async function fetchFile(filename) {
    try {
        const response = await fetch(filename);

        if (!response.ok) throw new Error('Failed to fetch document');
        return await response.text();
    } catch (error) {
        console.error(error);
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

    // Might be larger than the text if the size of the text is not a multiple of 512 bits (64 bytes)
    let overlay = streamA(Math.ceil(text.length/64), key);
    let ciphertext = xor(text, overlay, text.length);

    return ciphertext;

    // ---------------------------------------------------------------------------------------------------------------

    function streamA(amountOfBlocks, key){
        let allBlocks = new Uint8Array();

        let currentBlock = new Uint8Array(64);
        for(let i = 0; i < amountOfBlocks; i++){
            currentBlock = generateBlock(currentBlock, key);
            allBlocks = [...allBlocks, ...currentBlock];
        }

        function generateBlock(lastBlock, key) {
            return (new jsSHA("SHA-512", "UINT8ARRAY").update([...lastBlock, ...key]).getHash("UINT8ARRAY"));
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
    if(typeof stringOrArray === "string") stringOrArray = new TextEncoder("ASCII").encode(stringOrArray);
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

function uint8ArrayToInt8Array(inputArray){
    let outputArray = new Int8Array();
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
    console.log("Hex string: "+hexString);
    return Uint8Array.from(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
}

function _createFileData(text, key) {
    const fileName = toHexString(new TextEncoder().encode(defaultHash(key)));
    const content = encrypt(text, key);
    console.log("Name of file:\n"+fileName);
    console.log("Content:\n"+content);
}