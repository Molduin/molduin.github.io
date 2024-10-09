/**
 * Using any of the algorithms implemented here is discouraged.
 * They are probably insecure and are intended for educational/learning purposes only.
 * I have little idea what I am doing.
 */

import {jsSHA} from "./sha512";

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
    
    let amountOfBlocks = Math.ceil(text.length / 64);
    let ciphertext = new Uint8Array();
    let currentHash = new jsSHA("SHA-512", "UINT8ARRAY").update(key).getHash("UINT8ARRAY");
    for(let i = 0; i < amountOfBlocks; i++){
        // Generate key for block by salting previous hash with the key and hashing it
        currentHash = new jsSHA("SHA-512", "UINT8ARRAY").update(currentHash.push.apply(key)).getHash("UINT8ARRAY");
        let currentBlock = text.slice(i*64, i*64+63); // array.slice(inclusive, exclusive)
        ciphertext.push.apply(encryptBlock(currentBlock, currentHash));
    }

    function encryptBlock(textBlock, currentKey){

    }

    const shaObj = new jsSHA("SHA-512", "TEXT", { encoding: "UTF8" });
    /* .update() can be chained */
    shaObj.update("This is").update(" a ");
    shaObj.update("test");
    const hash = shaObj.getHash("HEX");
}

function decrypt(data) {

}