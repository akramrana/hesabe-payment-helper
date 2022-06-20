import { https, http } from "follow-redirects";
import { HesabeCrypt } from "hesabe-crypt-ts/lib"
import aesjs from "aes-js";

export class HesabeHelper {

    async payment(amount: number, transactionNumber: string, src: string = '') {
        const ivKey = "hesabe iv key";
        const encryptionKey = "hesabe encryption key";
        //
        let successUrl = "http://localhost:5000/hesabe/success";
        let errorUrl = "http://localhost:5000/hesabe/error";
        let returnUrl = "http://localhost:5000/hesabe/response";
        
        let total = Number(amount).toFixed(3);
        let TranTrackid: any = transactionNumber + Date.now();
        let udf1: any = "";
        let udf2: any = "";
        let udf3: any = "";
        let udf4: any = "";
        let udf5: any = "";
        
        const hisabebject: any = {
                amount: amount,
                currency: "KWD",
                paymentType: (src == 'src_card') ? "2" : "1",
                orderReferenceNumber: TranTrackid,
                version: "2.0",
                variable1: String(udf1),
                variable2: String(udf2),
                variable3: String(udf3),
                variable4: String(udf4),
                variable5: String(udf5),
                merchantCode: param.hesabeMerchantCode,
                responseUrl: returnUrl,
                failureUrl: returnUrl,
                name: "john doe",
                email: "john@yourmail.com",
                mobile_number: 12345678,
        };
        
        const postData = JSON.stringify(hisabebject);
        let encrypted = await this.encryptAES(postData, encryptionKey, ivKey);
        //
        let key = aesjs.utils.utf8.toBytes(encryptionKey);
        let iv = aesjs.utils.utf8.toBytes(ivKey);
        let instance = new HesabeCrypt();
        try {
            let hisabeResponseEnc: any = await this.sendHttpRequest(encrypted);
            let decrypted = instance.decryptAes(hisabeResponseEnc, key, iv);
            console.log({
                encrypted: encrypted,
                hisabeResponseEnc: hisabeResponseEnc,
                decrypted: decrypted,
            });
            let decodeJson = JSON.parse(decrypted);
            let paymentUrl = param.hesabePaymentUrl + "?data=" + decodeJson.response.data;
            console.log(paymentUrl);
            return paymentUrl;
        } catch (error) {
            console.log(error);
        }
    }

    async encryptAES(param: any, key: string, iv: string) {
        var cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        var encrypted = cipher.update(param, 'utf8', 'base64');
        encrypted += cipher.final('base64');
        //
        let base64decode = Buffer.from(encrypted, 'base64').toString('binary');
        let unpackStr = await this.unpack("C*", base64decode);
        let keys = [];
        let k, i, len;
        for (k in unpackStr) {
            if (unpackStr.hasOwnProperty(k)) {
                keys.push(k);
            }
        }
        keys.sort();
        len = keys.length;
        let sortedObj: any = {};
        for (i = 0; i < len; i++) {
            k = keys[i];
            sortedObj[k] = unpackStr[k];
        }
        let jsonStr = JSON.stringify(sortedObj);
        //console.log(jsonStr);
        var obj = JSON.parse(jsonStr);
        var dataArray = [];
        for (var o in obj) {
            dataArray.push(obj[o]);
        }
        //console.log(dataArray);
        let byteArray = new Uint8Array(dataArray);
        let hex = await this.toHexString(byteArray);
        let urlEncodeStr = encodeURIComponent(hex);
        return urlEncodeStr;
    }

    async unpack(format: string, data: any) {
        let formatPointer: any = 0,
            dataPointer: any = 0,
            result: any = {},
            instruction: any = '',
            quantifier: any = '',
            label: any = '',
            currentData: any = '',
            i: any = 0,
            j: any = 0,
            word: any = '',
            fbits: any = 0,
            ebits: any = 0,
            dataByteLength: any = 0;

        var fromIEEE754 = (bytes: any, ebits: any, fbits: any) => {
            // Bytes to bits
            var bits = [];
            for (var i = bytes.length; i; i -= 1) {
                var byte = bytes[i - 1];
                for (var j = 8; j; j -= 1) {
                    bits.push(byte % 2 ? 1 : 0);
                    byte = byte >> 1;
                }
            }
            bits.reverse();
            var str = bits.join('');
            // Unpack sign, exponent, fraction
            var bias = (1 << (ebits - 1)) - 1;
            var s = parseInt(str.substring(0, 1), 2) ? -1 : 1;
            var e = parseInt(str.substring(1, 1 + ebits), 2);
            var f = parseInt(str.substring(1 + ebits), 2);
            // Produce number
            if (e === (1 << ebits) - 1) {
                return f !== 0 ? NaN : s * Infinity;
            } else if (e > 0) {
                return s * Math.pow(2, e - bias) * (1 + f / Math.pow(2, fbits));
            } else if (f !== 0) {
                return s * Math.pow(2, -(bias - 1)) * (f / Math.pow(2, fbits));
            } else {
                return s * 0;
            }
        }
        while (formatPointer < format.length) {
            instruction = format.charAt(formatPointer);
            // Start reading 'quantifier'
            quantifier = '';
            formatPointer++;
            while ((formatPointer < format.length) &&
                (format.charAt(formatPointer).match(/[\d\*]/) !== null)) {
                quantifier += format.charAt(formatPointer);
                formatPointer++;
            }
            if (quantifier === '') {
                quantifier = '1';
            }
            // Start reading label
            label = '';
            while ((formatPointer < format.length) &&
                (format.charAt(formatPointer) !== '/')) {
                label += format.charAt(formatPointer);
                formatPointer++;
            }
            if (format.charAt(formatPointer) === '/') {
                formatPointer++;
            }
            var countLabel = 0;
            if (label == '') {
                label = ++countLabel
            }
            var currentResult: any;
            // Process given instruction
            switch (instruction) {
                case 'a': // NUL-padded string
                case 'A': // SPACE-padded string
                    if (quantifier === '*') {
                        quantifier = data.length - dataPointer;
                    } else {
                        quantifier = parseInt(quantifier, 10);
                    }
                    currentData = data.substr(dataPointer, quantifier);
                    dataPointer += quantifier;

                    if (instruction === 'a') {
                        currentResult = currentData.replace(/\0+$/, '');
                    } else {
                        currentResult = currentData.replace(/ +$/, '');
                    }
                    result[label] = currentResult;
                    break;

                case 'h': // Hex string, low nibble first
                case 'H': // Hex string, high nibble first
                    if (quantifier === '*') {
                        quantifier = data.length - dataPointer;
                    } else {
                        quantifier = parseInt(quantifier, 10);
                    }
                    currentData = data.substr(dataPointer, quantifier);
                    dataPointer += quantifier;

                    if (quantifier > currentData.length) {
                        throw new Error('Warning: unpack(): Type ' + instruction +
                            ': not enough input, need ' + quantifier);
                    }

                    currentResult = '';
                    for (i = 0; i < currentData.length; i++) {
                        word = currentData.charCodeAt(i).toString(16);
                        if (instruction === 'h') {
                            word = word[1] + word[0];
                        }
                        currentResult += word;
                    }
                    result[label] = currentResult;
                    break;

                case 'c': // signed char
                case 'C': // unsigned c
                    if (quantifier === '*') {
                        quantifier = data.length - dataPointer;
                    } else {
                        quantifier = parseInt(quantifier, 10);
                    }

                    currentData = data.substr(dataPointer, quantifier);
                    dataPointer += quantifier;

                    for (i = 0; i < currentData.length; i++) {
                        currentResult = currentData.charCodeAt(i);
                        if ((instruction === 'c') && (currentResult >= 128)) {
                            currentResult -= 256;
                        }
                        result[label + (quantifier > 1 ?
                            (i + 1) :
                            '')] = currentResult;
                    }
                    break;

                case 'S': // unsigned short (always 16 bit, machine byte order)
                case 's': // signed short (always 16 bit, machine byte order)
                case 'v': // unsigned short (always 16 bit, little endian byte order)
                    if (quantifier === '*') {
                        quantifier = (data.length - dataPointer) / 2;
                    } else {
                        quantifier = parseInt(quantifier, 10);
                    }

                    currentData = data.substr(dataPointer, quantifier * 2);
                    dataPointer += quantifier * 2;

                    for (i = 0; i < currentData.length; i += 2) {
                        // sum per word;
                        currentResult = ((currentData.charCodeAt(i + 1) & 0xFF) << 8) +
                            (currentData.charCodeAt(i) & 0xFF);
                        if ((instruction === 's') && (currentResult >= 32768)) {
                            currentResult -= 65536;
                        }
                        result[label + (quantifier > 1 ?
                            ((i / 2) + 1) :
                            '')] = currentResult;
                    }
                    break;

                case 'n': // unsigned short (always 16 bit, big endian byte order)
                    if (quantifier === '*') {
                        quantifier = (data.length - dataPointer) / 2;
                    } else {
                        quantifier = parseInt(quantifier, 10);
                    }

                    currentData = data.substr(dataPointer, quantifier * 2);
                    dataPointer += quantifier * 2;

                    for (i = 0; i < currentData.length; i += 2) {
                        // sum per word;
                        currentResult = ((currentData.charCodeAt(i) & 0xFF) << 8) +
                            (currentData.charCodeAt(i + 1) & 0xFF);
                        result[label + (quantifier > 1 ?
                            ((i / 2) + 1) :
                            '')] = currentResult;
                    }
                    break;

                case 'i': // signed integer (machine dependent size and byte order)
                case 'I': // unsigned integer (machine dependent size & byte order)
                case 'l': // signed long (always 32 bit, machine byte order)
                case 'L': // unsigned long (always 32 bit, machine byte order)
                case 'V': // unsigned long (always 32 bit, little endian byte order)
                    if (quantifier === '*') {
                        quantifier = (data.length - dataPointer) / 4;
                    } else {
                        quantifier = parseInt(quantifier, 10);
                    }

                    currentData = data.substr(dataPointer, quantifier * 4);
                    dataPointer += quantifier * 4;

                    for (i = 0; i < currentData.length; i += 4) {
                        currentResult =
                            ((currentData.charCodeAt(i + 3) & 0xFF) << 24) +
                            ((currentData.charCodeAt(i + 2) & 0xFF) << 16) +
                            ((currentData.charCodeAt(i + 1) & 0xFF) << 8) +
                            ((currentData.charCodeAt(i) & 0xFF));
                        result[label + (quantifier > 1 ?
                            ((i / 4) + 1) :
                            '')] = currentResult;
                    }

                    break;

                case 'N': // unsigned long (always 32 bit, little endian byte order)
                    if (quantifier === '*') {
                        quantifier = (data.length - dataPointer) / 4;
                    } else {
                        quantifier = parseInt(quantifier, 10);
                    }

                    currentData = data.substr(dataPointer, quantifier * 4);
                    dataPointer += quantifier * 4;

                    for (i = 0; i < currentData.length; i += 4) {
                        currentResult =
                            ((currentData.charCodeAt(i) & 0xFF) << 24) +
                            ((currentData.charCodeAt(i + 1) & 0xFF) << 16) +
                            ((currentData.charCodeAt(i + 2) & 0xFF) << 8) +
                            ((currentData.charCodeAt(i + 3) & 0xFF));
                        result[label + (quantifier > 1 ?
                            ((i / 4) + 1) :
                            '')] = currentResult;
                    }

                    break;

                case 'f': //float
                case 'd': //double
                    ebits = 8;
                    fbits = (instruction === 'f') ? 23 : 52;
                    dataByteLength = 4;
                    if (instruction === 'd') {
                        ebits = 11;
                        dataByteLength = 8;
                    }

                    if (quantifier === '*') {
                        quantifier = (data.length - dataPointer) / dataByteLength;
                    } else {
                        quantifier = parseInt(quantifier, 10);
                    }

                    currentData = data.substr(dataPointer, quantifier * dataByteLength);
                    dataPointer += quantifier * dataByteLength;

                    for (i = 0; i < currentData.length; i += dataByteLength) {
                        data = currentData.substr(i, dataByteLength);

                        var bytes = [];
                        for (j = data.length - 1; j >= 0; --j) {
                            bytes.push(data.charCodeAt(j));
                        }
                        result[label + (quantifier > 1 ?
                            ((i / 4) + 1) :
                            '')] = fromIEEE754(bytes, ebits, fbits);
                    }

                    break;

                case 'x': // NUL byte
                case 'X': // Back up one byte
                case '@': // NUL byte
                    if (quantifier === '*') {
                        quantifier = data.length - dataPointer;
                    } else {
                        quantifier = parseInt(quantifier, 10);
                    }

                    if (quantifier > 0) {
                        if (instruction === 'X') {
                            dataPointer -= quantifier;
                        } else {
                            if (instruction === 'x') {
                                dataPointer += quantifier;
                            } else {
                                dataPointer = quantifier;
                            }
                        }
                    }
                    break;

                default:
                    throw new Error('Warning:  unpack() Type ' + instruction +
                        ': unknown format code');
            }
        }
        return result;
    }

    async toHexString(byteArray: any) {
        return Array.prototype.map.call(byteArray, function (byte) {
            return ('0' + (byte & 0xFF).toString(16)).slice(-2);
        }).join('');
    }

    async sendHttpRequest(postData: any) {
        let result = new Promise((resolve, reject) => {
            const options: any = {
                method: 'POST',
                hostname: "sandbox.hesabe.com",
                path: "/checkout",
                rejectUnauthorized: false,
                headers: {
                    'accessCode': "hesabe access code",
                    'Content-Type': 'application/json'
                },
                maxRedirects: 20,
            }
            let req = https.request(options, function (res: any) {
                let chunks: any = [];
                res.on("data", function (chunk: any) {
                    chunks.push(chunk);
                });
                res.on("end", function (chunk: any) {
                    let body = Buffer.concat(chunks);
                    resolve(body.toString());
                });
                res.on("error", function (error: any) {
                    console.error(error);
                    resolve(error);
                });
            });
            var formData = "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"data\"\r\n\r\n" + postData + "\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--";;
            req.setHeader('content-type', 'multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW');
            req.write(formData);
            req.end();
        });
        return result;
    }
}
