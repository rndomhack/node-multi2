/* eslint no-fallthrough: 0 */
"use strict";

class Multi2 {
    constructor() {
        this._round = 4;
        this._systemKey = null;
        this._initialCbc = null;
        this._workKeyOdd = null;
        this._workKeyEven = null;
    }

    setRound(round) {
        this._round = round;
    }

    setSystemKey(buffer) {
        this._systemKey = {
            key1: (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3],
            key2: (buffer[4] << 24) | (buffer[5] << 16) | (buffer[6] << 8) | buffer[7],
            key3: (buffer[8] << 24) | (buffer[9] << 16) | (buffer[10] << 8) | buffer[11],
            key4: (buffer[12] << 24) | (buffer[13] << 16) | (buffer[14] << 8) | buffer[15],
            key5: (buffer[16] << 24) | (buffer[17] << 16) | (buffer[18] << 8) | buffer[19],
            key6: (buffer[20] << 24) | (buffer[21] << 16) | (buffer[22] << 8) | buffer[23],
            key7: (buffer[24] << 24) | (buffer[25] << 16) | (buffer[26] << 8) | buffer[27],
            key8: (buffer[28] << 24) | (buffer[29] << 16) | (buffer[30] << 8) | buffer[31]
        };
    }

    setInitialCbc(buffer) {
        this._initialCbc = {
            left: (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3],
            right: (buffer[4] << 24) | (buffer[5] << 16) | (buffer[6] << 8) | buffer[7]
        };
    }

    setScrambleKey(buffer) {
        const scrambleKeyOdd = {
            left: (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3],
            right: (buffer[4] << 24) | (buffer[5] << 16) | (buffer[6] << 8) | buffer[7]
        };

        const scrambleKeyEven = {
            left: (buffer[8] << 24) | (buffer[9] << 16) | (buffer[10] << 8) | buffer[11],
            right: (buffer[12] << 24) | (buffer[13] << 16) | (buffer[14] << 8) | buffer[15]
        };

        this._workKeyOdd = {};
        this._workKeyEven = {};

        this._keySchedule(this._workKeyOdd, this._systemKey, scrambleKeyOdd);
        this._keySchedule(this._workKeyEven, this._systemKey, scrambleKeyEven);
    }

    decrypt(buffer, isEven) {
        const workKey = isEven ? this._workKeyEven : this._workKeyOdd;

        let srcLeft, srcRight, destLeft, destRight;

        let cbcLeft = this._initialCbc.left;
        let cbcRight = this._initialCbc.right;

        const bufferLength = buffer.length;
        const remainStart = bufferLength & 0xFFFFFFF8;
        const remainLength = bufferLength & 0x00000007;

        let bytesRead = 0;

        let y, z, a, b, c;

        while (bytesRead < remainStart) {
            srcLeft = destLeft = (buffer[bytesRead] << 24) | (buffer[bytesRead + 1] << 16) | (buffer[bytesRead + 2] << 8) | buffer[bytesRead + 3];
            srcRight = destRight = (buffer[bytesRead + 4] << 24) | (buffer[bytesRead + 5] << 16) | (buffer[bytesRead + 6] << 8) | buffer[bytesRead + 7];

            for (let i = 0; i < this._round; i++) {
                // pi4
                y = (destRight + workKey.key8) | 0;

                destLeft ^= ((((y << 2) | (y >>> (32 - 2))) | 0) + y + 1) | 0;

                // pi3
                y = (destLeft + workKey.key6) | 0;
                z = ((((y << 2) | (y >>> (32 - 2))) | 0) + y + 1) | 0;
                a = ((((z << 8) | (z >>> (32 - 8))) | 0) ^ z) | 0;
                b = (a + workKey.key7) | 0;
                c = ((((b << 1) | (b >>> (32 - 1))) | 0) - b) | 0;

                destRight ^= ((((c << 16) | (c >>> (32 - 16))) | 0) ^ (c | destLeft)) | 0;

                // pi2
                y = (destRight + workKey.key5) | 0;
                z = ((((y << 1) | (y >>> (32 - 1))) | 0) + y - 1) | 0;

                destLeft ^= ((((z << 4) | (z >>> (32 - 4))) | 0) ^ z) | 0;

                // pi1
                destRight ^= destLeft;

                // pi4
                y = (destRight + workKey.key4) | 0;

                destLeft ^= ((((y << 2) | (y >>> (32 - 2))) | 0) + y + 1) | 0;

                // pi3
                y = (destLeft + workKey.key2) | 0;
                z = ((((y << 2) | (y >>> (32 - 2))) | 0) + y + 1) | 0;
                a = ((((z << 8) | (z >>> (32 - 8))) | 0) ^ z) | 0;
                b = (a + workKey.key3) | 0;
                c = ((((b << 1) | (b >>> (32 - 1))) | 0) - b) | 0;

                destRight ^= ((((c << 16) | (c >>> (32 - 16))) | 0) ^ (c | destLeft)) | 0;

                // pi2
                y = (destRight + workKey.key1) | 0;
                z = ((((y << 1) | (y >>> (32 - 1))) | 0) + y - 1) | 0;

                destLeft ^= ((((z << 4) | (z >>> (32 - 4))) | 0) ^ z) | 0;

                // pi1
                destRight ^= destLeft;
            }

            destLeft ^= cbcLeft;
            destRight ^= cbcRight;

            cbcLeft = srcLeft;
            cbcRight = srcRight;

            buffer[bytesRead] = (destLeft >>> 24) & 0xFF;
            buffer[bytesRead + 1] = (destLeft >>> 16) & 0xFF;
            buffer[bytesRead + 2] = (destLeft >>> 8) & 0xFF;
            buffer[bytesRead + 3] = destLeft & 0xFF;

            buffer[bytesRead + 4] = (destRight >>> 24) & 0xFF;
            buffer[bytesRead + 5] = (destRight >>> 16) & 0xFF;
            buffer[bytesRead + 6] = (destRight >>> 8) & 0xFF;
            buffer[bytesRead + 7] = destRight & 0xFF;

            bytesRead += 8;
        }

        if (remainLength > 0) {
            for (let i = 0; i < this._round; i++) {
                // pi1
                cbcRight ^= cbcLeft;

                // pi2
                y = (cbcRight + workKey.key1) | 0;
                z = ((((y << 1) | (y >>> (32 - 1))) | 0) + y - 1) | 0;

                cbcLeft ^= ((((z << 4) | (z >>> (32 - 4))) | 0) ^ z) | 0;

                // pi3
                y = (cbcLeft + workKey.key2) | 0;
                z = ((((y << 2) | (y >>> (32 - 2))) | 0) + y + 1) | 0;
                a = ((((z << 8) | (z >>> (32 - 8))) | 0) ^ z) | 0;
                b = (a + workKey.key3) | 0;
                c = ((((b << 1) | (b >>> (32 - 1))) | 0) - b) | 0;

                cbcRight ^= ((((c << 16) | (c >>> (32 - 16))) | 0) ^ (c | cbcLeft)) | 0;

                // pi4
                y = (cbcRight + workKey.key4) | 0;

                cbcLeft ^= ((((y << 2) | (y >>> (32 - 2))) | 0) + y + 1) | 0;

                // pi1
                cbcRight ^= cbcLeft;

                // pi2
                y = (cbcRight + workKey.key5) | 0;
                z = ((((y << 1) | (y >>> (32 - 1))) | 0) + y - 1) | 0;

                cbcLeft ^= ((((z << 4) | (z >>> (32 - 4))) | 0) ^ z) | 0;

                // pi3
                y = (cbcLeft + workKey.key6) | 0;
                z = ((((y << 2) | (y >>> (32 - 2))) | 0) + y + 1) | 0;
                a = ((((z << 8) | (z >>> (32 - 8))) | 0) ^ z) | 0;
                b = (a + workKey.key7) | 0;
                c = ((((b << 1) | (b >>> (32 - 1))) | 0) - b) | 0;

                cbcRight ^= ((((c << 16) | (c >>> (32 - 16))) | 0) ^ (c | cbcLeft)) | 0;

                // pi4
                y = (cbcRight + workKey.key8) | 0;

                cbcLeft ^= ((((y << 2) | (y >>> (32 - 2))) | 0) + y + 1) | 0;

            }

            switch (remainLength) {
                case 7: buffer[bytesRead + 6] ^= (cbcRight >>> 8) & 0xFF;
                case 6: buffer[bytesRead + 5] ^= (cbcRight >>> 16) & 0xFF;
                case 5: buffer[bytesRead + 4] ^= (cbcRight >>> 24) & 0xFF;
                case 4: buffer[bytesRead + 3] ^= cbcLeft & 0xFF;
                case 3: buffer[bytesRead + 2] ^= (cbcLeft >>> 8) & 0xFF;
                case 2: buffer[bytesRead + 1] ^= (cbcLeft >>> 16) & 0xFF;
                case 1: buffer[bytesRead] ^= (cbcLeft >>> 24) & 0xFF;
            }
        }
    }

    _keySchedule(workKey, systemKey, dataKey) {
        let y, z, a, b, c;

        // pi1
        dataKey.right ^= dataKey.left;

        // pi2
        y = (dataKey.right + systemKey.key1) | 0;
        z = ((((y << 1) | (y >>> (32 - 1))) | 0) + y - 1) | 0;

        dataKey.left ^= ((((z << 4) | (z >>> (32 - 4))) | 0) ^ z) | 0;

        workKey.key1 = dataKey.left;

        // pi3
        y = (dataKey.left + systemKey.key2) | 0;
        z = ((((y << 2) | (y >>> (32 - 2))) | 0) + y + 1) | 0;
        a = ((((z << 8) | (z >>> (32 - 8))) | 0) ^ z) | 0;
        b = (a + systemKey.key3) | 0;
        c = ((((b << 1) | (b >>> (32 - 1))) | 0) - b) | 0;

        dataKey.right ^= ((((c << 16) | (c >>> (32 - 16))) | 0) ^ (c | dataKey.left)) | 0;

        workKey.key2 = dataKey.right;

        // pi4
        y = (dataKey.right + systemKey.key4) | 0;

        dataKey.left ^= ((((y << 2) | (y >>> (32 - 2))) | 0) + y + 1) | 0;

        workKey.key3 = dataKey.left;

        // pi1
        dataKey.right ^= dataKey.left;

        workKey.key4 = dataKey.right;

        // pi2
        y = (dataKey.right + systemKey.key5) | 0;
        z = ((((y << 1) | (y >>> (32 - 1))) | 0) + y - 1) | 0;

        dataKey.left ^= ((((z << 4) | (z >>> (32 - 4))) | 0) ^ z) | 0;

        workKey.key5 = dataKey.left;

        // pi3
        y = (dataKey.left + systemKey.key6) | 0;
        z = ((((y << 2) | (y >>> (32 - 2))) | 0) + y + 1) | 0;
        a = ((((z << 8) | (z >>> (32 - 8))) | 0) ^ z) | 0;
        b = (a + systemKey.key7) | 0;
        c = ((((b << 1) | (b >>> (32 - 1))) | 0) - b) | 0;

        dataKey.right ^= ((((c << 16) | (c >>> (32 - 16))) | 0) ^ (c | dataKey.left)) | 0;

        workKey.key6 = dataKey.right;

        // pi4
        y = (dataKey.right + systemKey.key8) | 0;

        dataKey.left ^= ((((y << 2) | (y >>> (32 - 2))) | 0) + y + 1) | 0;

        workKey.key7 = dataKey.left;

        // pi1
        dataKey.right ^= dataKey.left;

        workKey.key8 = dataKey.right;
    }
}

module.exports = Multi2;
