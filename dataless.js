/* 
 * Dataless : encrypt data with WebCrypto API.
 * https://github.com/joannesource/dataless.git
 */


var Dataless = {
    passwordHash: null,
    wrappedMasterKey: null,
    unwrappedMasterKey: null,
    wrapperKey: null,
    setup: function () {
        var self = this;
        if (!self.exists()) {
            return self.create().then(function () {
                if (self.exists()) {
                    return self.load().then(function () {
                        if (!self.unwrappedMasterKey)
                            return Promise.reject('Dataless failed to load');
                        else
                            return true;
                    });
                } else {
                    console.error('Dataless failed to create a new key');
                    return;
                }
            });
        } else {
            return self.load().then(function () {
                if (!self.unwrappedMasterKey)
					return Promise.reject('Dataless failed to load');
                else
                    return true;
            });
        }
    },
    arrayBufferToString: function (buffer) {
        var binary = '';
        var bytes = new Uint8Array(buffer);
        var len = bytes.byteLength;
        for (var i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[ i ]);
        }
        return binary;
    },
    stringToArrayBuffer: function (string) {
        var len = string.length;
        var buffer = new ArrayBuffer(len);
        var bytes = new Uint8Array(buffer);
        for (var i = 0; i < len; i++) {
            bytes[i] = string.charCodeAt(i);
        }
        return bytes;
    },
    exists: function () {
        return localStorage.getItem('Dataless') !== 'null' && localStorage.getItem('Dataless') != null;
    },
    create: function () {
        var self = this;

        // Generates random master key.
        return window.crypto.subtle.generateKey(
                {
                    name: "AES-GCM",
                    length: 256
                },
                true, // extractable
                ["encrypt", "decrypt"]
                )
                .then(function (key) {
                    return self.iv(self.passwordHash, 16).then(function (derivedIv) {
                        return window.crypto.subtle.wrapKey(
                                "jwk", //can be "jwk", "raw", "spki", or "pkcs8"
                                key, //the key you want to wrap, must be able to export to above format
                                self.wrapperKey, //the AES-CBC key with "wrapKey" usage flag
                                {//these are the wrapping key's algorithm options
                                    name: "AES-CBC",
                                    iv: derivedIv,
                                })
                                .then(function (wrapped) {
                                    //returns an ArrayBuffer containing the encrypted data
                                    self.wrappedMasterKey = new Uint8Array(wrapped);
                                    localStorage.setItem('Dataless', self.arrayBufferToString(wrapped));
                                })
                                .catch(function (err) {
                                    console.error(err);
                                });
                    });
                })
                .catch(function (err) {
                    console.error(err);
                });
    },
    unload: function () {
        passwordHash = null;
        wrappedMasterKey = null;
        unwrappedMasterKey = null;
        wrapperKey = null;
    },
    isLoaded: function () {
        return this.unwrappedMasterKey != null;
    },
    load: function () {
        // Loads the master key.
        var self = this;
        var wrappedKey = self.stringToArrayBuffer(localStorage.getItem('Dataless'));

        return self.iv(self.passwordHash, 16).then(function (derivedIv) {
            return window.crypto.subtle.unwrapKey(
                    "jwk", //"jwk", "raw", "spki", or "pkcs8" (whatever was used in wrapping)
                    wrappedKey, //the key you want to unwrap
                    self.wrapperKey,
                    {
                        name: "AES-CBC",
                        iv: derivedIv
                    },
                    {
                        name: "AES-GCM",
                        length: 256
                    },
                    true, //whether the key is extractable (i.e. can be used in exportKey)
                    ["encrypt", "decrypt"] //the usages you want the unwrapped key to have
                    )
                    .then(function (key) {
                        self.unwrappedMasterKey = key;
                    })
                    .catch(function (err) {
                        console.error(err);
                    });
        });
    },
    encrypt: function (_data) {
        var self = this;
        var iv = window.crypto.getRandomValues(new Uint8Array(12));
        var _dataString = JSON.stringify(_data);
        var data = new TextEncoder("utf-8").encode(_dataString);

        return window.crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv: iv,
                    tagLength: 128,
                },
                self.unwrappedMasterKey,
                data //ArrayBuffer
                )
                .then(function (encrypted) {//ArrayBuffer
                    return {
                        iv: btoa(self.arrayBufferToString(iv)),
                        e: btoa(self.arrayBufferToString(encrypted))
                    };
                })
                .catch(function (err) {
                    console.error(err);
                });
    },
    decrypt: function (object) {
        var self = this;
        var iv = self.stringToArrayBuffer(atob(object.iv));
        var encryptedData = self.stringToArrayBuffer(atob(object.e));

        return window.crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: iv,
                    tagLength: 128,
                },
                self.unwrappedMasterKey, //from generateKey or importKey above
                encryptedData //ArrayBuffer
                )
                .then(function (decrypted) {//ArrayBuffer
                    var data = new TextDecoder("utf-8").decode(decrypted);
                    var parsed = JSON.parse(data);
                    return parsed;
                })
                .catch(function (err) {
                    console.error(err);
                });
    },
    iv: function (inputString, ivLen) {
        // Derive an IV of desired length using an input string.
        return window.crypto.subtle.digest(
                {
                    name: "SHA-256",
                },
                new Uint8Array(this.stringToArrayBuffer(inputString.repeat(12)))// custom input string expansion salt
                )
                .then(function (hash) {// ArrayBuffer
                    return new Uint8Array(hash).slice(0, ivLen);// IV of desired length
                })
                .catch(function (err) {
                    console.error(err);
                });
    },
    setPassword: function (password) {
        // Uses a password to derive a key wrapper from its salted hash.
        var self = this;
        return window.crypto.subtle.digest(
                {
                    name: "SHA-256",
                },
                new Uint8Array(this.stringToArrayBuffer(password))
                )
                .then(function (hash) {
                    self.passwordHash = self.arrayBufferToString(hash);
                    return window.crypto.subtle.importKey(
                            "raw",
                            hash,
                            {
                                name: "AES-CBC",
                            },
                            true, // extractable
                            ["encrypt", "decrypt", "wrapKey", "unwrapKey"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
                            )
                            .then(function (key) {
                                self.wrapperKey = key;
                            })
                            .catch(function (err) {
                                console.error(err);
                            });
                })
                .catch(function (err) {
                    console.error(err);
                });
    },
    export: function () {
        return {
            wrappedMasterKey: btoa(localStorage.getItem('Dataless')),
        }
    },
    import: function (access) {
        localStorage.setItem('Dataless', atob(access.wrappedMasterKey));
        return this.load();
    }
}
module.exports = Dataless;
