# Searchable Encryption

Searchable encryption provides basic functions that is required in the schemes of index-based symmetric searchable encryption, with the goal to be simple, fast and secure. To keep this package easy to use, some cryptographic configurations are taken beforehand by the contributors to this package, such that the provided functionaries are secure. This is build on top of [WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API), which expose low-level cryptographic primitives to browser based applications; hence `searchable-encryption` is much faster, and maintains tiny bundle-size! 😎

## Get started!

`npm i --save searchable-encryption`

Then ...

```js
import se from 'query-string-modifier';

const key = se.genSecretKey();

const data = [
    'Highly secure data!',
    'Long textual representation ..',
    'or any type of data as an ArrayBuffer ..',
    'with custom function to extract ..',
    'the keywords from each data entry'
]

// TBD

...

```

## API v1

```js
/**
 * Build index table for given collection of documents.
 * @param {{pointer: string, data: T}[]} documents collection of files/documents as an array of { pointer, data },
 *    where pointer is unique string that used to refer to this document in the database.
 * @param {CryptoKey} secretKey this secret is used as salt when creating trapdoors, i.e. hashing the keywords.
 * @param {(data: T) => (string[] | ArrayBuffer[])} [getKeywords] given a document.data, return all DISTINCT keywords associated to this document.
 *      Default is function that extract all distinct tokens from a string, in case document.data is of type string.
 * @returns object where each key is a trapdoor that its value is array of pointers to the associated documents.
 */
 export async function buildIndex(documents = [], key, getKeywords) { ... }

/**
 * Get the trapdoor for given query and secretKey
 * @param {string|ArrayBuffer} query the search query
 * @param {KeyObject} secretKey this should have secretSalt attribute to use for hashing
 * @returns string represent the trapdoor
 */
export async function trapdoor(query, key) { ... }

/**
 * Generate a symmetric secret key for AES-CBC encryption algorithm,
 * with initial vector (iv), based on given secret (password) and salt.
 * This algorithm is deterministic, given the same secret and salt. If salt isn
 * @param {string} [secret="PASSPHRASE"]  textual based to derive the password from, e.g. password.
 * @param {object} options
 * @param {string} [options.hash="SHA-256"] the hashing algorithm for deriving bits used by `PBKDF2` algorithm, e.g. 'SHA-256'.
 *    Please refer to `PBKDF2` specification for supported hashing algorithms.
 * @param {string|ArrayBuffer} [options.salt] default value is a secure random value is used.
 *    For deterministic key generation, please provide the same salt.
 * @param {number} [options.iterations=999] the number of iteration performed by `PBKDF2` algorithm.
 * @param {number} [options.keyLengthByte=48] the length of the generated key in byte;
 *    however, only the first 32 byte (256-bit) are used for AES and last 16 byte (128-bit) for the initial vector, hence the default value 48.
 * @returns object in form of {key, iv}, where the (key) is the created CryptoKey, and the (iv) is 16 byte ArrayBuffer
 */
export async function genSecretKey(secret = "PASSPHRASE", options = {}) { ... }

// ------------ Basic Cryptography functions ------------

/**
 * Encrypt textual based data using the AES-CBC encryption algorithm.
 * @param {string} text string text to be encrypted.
 * @param {{key: CryptoKey, iv: ArrayBuffer}} keyObject object in form of {key, iv}
 * @param {'hex'|'utf-8'|'ascii'|'base64'|'..etc'} [encoding='hex'] the encoding of the encrypted text; default: 'hex'.
 * @returns textual representation of the encrypted data
 */
export async function encrypt(text, keyObject, encoding) { ... }

/**
 * Decrypt textual representation of encrypted data using the AES-CBC encryption algorithm.
 * @param {string} encryptedText textual representation of the encrypted data.
 * @param {{key: CryptoKey, iv: ArrayBuffer}} keyObject object in form of {key, iv}
 * @param {'hex'|'utf-8'|'ascii'|'base64'|'..etc'} [encoding='hex'] the encoding of the encrypted text; default: 'hex'.
 * @returns
 */
export async function decrypt(encryptedData, keyObject, encoding) { ... }

/**
 * Digest (hash) String or ArrayBuffer data.
 * Optionally with salt.
 * @param {string|ArrayBuffer} data
 * @param {object} [options]
 * @param {"SHA-1"|"SHA-256"|"SHA-384"|"SHA-512"} [options.hash] the algorithm to be used for hashing; default is SHA-256.
 * @param {string|ArrayBuffer} [options.salt] the salt is used for difusing the text before hashing.
 * @returns textual representation default 'hex' of the hash.
 */
export async function digest(data, options = {}) { ... }

// ------------ Utile functions ------------

/**
 * Concat two or multiple ArrayBuffer passed as arguments.
 * @param  {...ArrayBuffer} buffers buffers passed as multiple arguments.
 * @returns ArrayBuffer resulted by concatenating the given buffers.
 */
function abConcat(...buffers) { ... }

/**
 * Convert ArrayBuffer object to string representation given an encoding
 * @param {ArrayBuffer} arrayBuffer an ArrayBuffer object or one of its view, e.g. Uint8Array object
 * @param {'hex'|'utf-8'|'ascii'|'base64'|'..etc'} [encoding] Any valid Buffer object encoding
 * @returns
 */
export function ab2str(arrayBuffer, encoding = "hex") { ... }

/**
 * Convert string representation of data in given encoding to ArrayBuffer object
 * @param {string} string
 * @param {'hex'|'utf-8'|'ascii'|'base64'|'..etc'} [encoding] Any valid Buffer object encoding
 */
export function str2ab(string, encoding = "hex") { ... }
```
