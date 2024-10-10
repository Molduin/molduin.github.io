/**
 * Using any of the algorithms implemented here is discouraged.
 * They are probably insecure and are intended for educational/learning purposes only.
 * I have little idea what I am doing.
 */

// import {jsSHA} from "./sha512";

fetchFile("Files/index.txt");

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

const globalSalt = [177, 211, 123, 249, 2, 30, 164, 89, 87, 96, 24, 156, 216, 182, 206, 199];

let ciphertext = encrypt("Hello, world!","hunter2");
console.log(ciphertext); // Should be some byte salad
let decrypted = encrypt(ciphertext, "hunter2");
console.log(new TextDecoder().decode(decrypted)); // Should say "Hello, world!"

//console.log("Hello");

/**
 * 
 * @param {(string|Uint8Array)} text - Text to be encrypted
 * @param {(string|Uint8Array)} key - Encryption key or password
 */
function encrypt(text, key) {
    if(typeof text === "string") text = new TextEncoder().encode(text);
    else if(!typeof text === "UInt8Array") throw new Error();
    if(typeof key === "string") key = new TextEncoder().encode(key);
    else if(!typeof key === "UInt8Array") throw new Error();

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

function multiHash(input, iterationArray, iterations) {
    let output = input;
    for(let i = 0; i < iterations; i++){
        for (let j = 0; j < iterationArray.length; j++) {
            let concatenate = false;
            for (let k = 0; k < iterationArray[j]; k++) {
                let shaObj = new jsSHA("SHA-512", "UINT8ARRAY");
                if (concatenate) output = [...output, ...input];
                output = shaObj.update(output).getHash("UINT8ARRAY");
            }
            concatenate = !concatenate;
        }
    }
    return output;
}

async function fetchFile(filename) {
    try {
        const response = await fetch(filename);

        if (!response.ok) throw new Error('Failed to fetch document');
        let data = await response.text();
        console.log(data);
        return data;
    } catch (error) {
        console.error(error);
    }
}