package com.example.trolonciobot.crypto;

import java.util.Arrays;

/**
 * AES-256 implementado desde cero con una modificación clave:
 * la S-Box de SubBytes se genera dinámicamente a partir de la clave de sesión
 * en lugar de usar la tabla fija estándar.
 *
 * Esto significa que cada conversación tiene su propia tabla de sustitución,
 * haciendo que las técnicas de criptoanálisis basadas en la S-Box estándar
 * no sean aplicables directamente.
 *
 * El Key Schedule usa la S-Box estándar para mantener la expansión de clave
 * independiente del orden de la S-Box dinámica.
 */
public class AESModified {

    private static final int BLOCK_SIZE = 16;  // bytes por bloque
    private static final int KEY_SIZE   = 32;  // bytes de clave (AES-256)
    private static final int NR         = 14;  // rondas AES-256
    private static final int NK         = 8;   // palabras en la clave

    // Constantes de ronda para el Key Schedule (potencias de 2 en GF(2^8))
    private static final int[] RCON = {
            0x00000000,
            0x01000000, 0x02000000, 0x04000000, 0x08000000,
            0x10000000, 0x20000000, 0x40000000, 0x80000000,
            0x1b000000, 0x36000000
    };

    // S-Box ESTÁNDAR de AES — usada solo en el Key Schedule
    private static final int[] SBOX_STD = {
            0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
            0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
            0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
            0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
            0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
            0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
            0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
            0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
            0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
            0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
            0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
            0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
            0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
            0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
            0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
            0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
    };

    // S-Box dinámica generada desde la clave de sesión
    private final byte[] sbox;
    private final byte[] sboxInv;
    // 60 palabras = 15 claves de ronda × 4 palabras de 4 bytes
    private final int[]  roundKeys;

    public AESModified(byte[] clave) {
        if (clave.length != KEY_SIZE) {
            throw new IllegalArgumentException("La clave AES debe ser de 32 bytes.");
        }
        this.sbox      = generarSBox(clave);
        this.sboxInv   = generarSBoxInversa(sbox);
        this.roundKeys = expandirClave(clave);
    }

    // ──────────────────────────────────────────────────────────
    //  S-BOX DINÁMICA
    // ──────────────────────────────────────────────────────────

    /**
     * Genera la S-Box usando Fisher-Yates con la clave como semilla.
     *
     * El algoritmo baraja los 256 valores [0..255] de forma determinista:
     * dados los mismos bytes de clave, produce siempre la misma permutación.
     * El resultado garantiza que cada valor aparece exactamente una vez,
     * condición necesaria para que SubBytes sea reversible.
     */
    private static byte[] generarSBox(byte[] clave) {
        int[] s = new int[256];
        for (int i = 0; i < 256; i++) s[i] = i;

        int j = 0;
        for (int i = 255; i > 0; i--) {
            // j incorpora el valor actual y un byte de la clave en esa posición
            j = (j + s[i] + (clave[i % clave.length] & 0xFF)) % (i + 1);
            int tmp = s[i]; s[i] = s[j]; s[j] = tmp;
        }

        byte[] result = new byte[256];
        for (int i = 0; i < 256; i++) result[i] = (byte) s[i];
        return result;
    }

    /**
     * Genera la S-Box inversa: si sbox[i] = v, entonces sboxInv[v] = i.
     * Permite deshacer SubBytes durante el descifrado.
     */
    private static byte[] generarSBoxInversa(byte[] sbox) {
        byte[] inv = new byte[256];
        for (int i = 0; i < 256; i++) {
            inv[sbox[i] & 0xFF] = (byte) i;
        }
        return inv;
    }

    // ──────────────────────────────────────────────────────────
    //  KEY SCHEDULE — expansión de clave a 15 subclaves
    // ──────────────────────────────────────────────────────────

    /**
     * Expande la clave de 32 bytes en 60 palabras de 4 bytes (15 claves de ronda).
     *
     * AES-256 usa NK=8 palabras iniciales. Para i >= 8:
     *   - Si i % 8 == 0: aplica RotWord + SubWord(estándar) + XOR con Rcon
     *   - Si i % 8 == 4: aplica SubWord(estándar) — exclusivo de AES-256
     *   - Resto: W[i] = W[i-8] XOR W[i-1]
     *
     * Se usa la S-Box ESTÁNDAR aquí (no la dinámica) para que la expansión
     * de clave sea independiente del orden de la S-Box de cifrado.
     */
    private static int[] expandirClave(byte[] clave) {
        int[] W = new int[4 * (NR + 1)];

        // Cargar la clave como 8 palabras de 32 bits
        for (int i = 0; i < NK; i++) {
            W[i] = ((clave[4*i]   & 0xFF) << 24)
                    | ((clave[4*i+1] & 0xFF) << 16)
                    | ((clave[4*i+2] & 0xFF) <<  8)
                    |  (clave[4*i+3] & 0xFF);
        }

        for (int i = NK; i < W.length; i++) {
            int temp = W[i - 1];
            if (i % NK == 0) {
                temp = subWordEstandar(rotWord(temp)) ^ RCON[i / NK];
            } else if (i % NK == 4) {
                temp = subWordEstandar(temp);
            }
            W[i] = W[i - NK] ^ temp;
        }

        return W;
    }

    // Rota la palabra 1 byte a la izquierda: [a,b,c,d] → [b,c,d,a]
    private static int rotWord(int w) {
        return (w << 8) | (w >>> 24);
    }

    // Aplica la S-Box ESTÁNDAR a cada byte de la palabra (usado en Key Schedule)
    private static int subWordEstandar(int w) {
        return (SBOX_STD[(w >>> 24) & 0xFF] << 24)
                | (SBOX_STD[(w >>> 16) & 0xFF] << 16)
                | (SBOX_STD[(w >>>  8) & 0xFF] <<  8)
                |  SBOX_STD[ w         & 0xFF];
    }

    // ──────────────────────────────────────────────────────────
    //  OPERACIONES DE RONDA — CIFRADO
    // ──────────────────────────────────────────────────────────

    // Sustituye cada byte del estado usando la S-Box dinámica
    private void subBytes(byte[][] state) {
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                state[r][c] = sbox[state[r][c] & 0xFF];
    }

    // Desplaza cada fila r del estado r posiciones a la izquierda
    private static void shiftRows(byte[][] state) {
        byte tmp;

        // Fila 1: desplazar 1 posición izquierda
        tmp = state[1][0];
        state[1][0] = state[1][1]; state[1][1] = state[1][2];
        state[1][2] = state[1][3]; state[1][3] = tmp;

        // Fila 2: desplazar 2 posiciones (= intercambiar pares)
        tmp = state[2][0]; state[2][0] = state[2][2]; state[2][2] = tmp;
        tmp = state[2][1]; state[2][1] = state[2][3]; state[2][3] = tmp;

        // Fila 3: desplazar 3 posiciones izquierda (= 1 posición derecha)
        tmp = state[3][3];
        state[3][3] = state[3][2]; state[3][2] = state[3][1];
        state[3][1] = state[3][0]; state[3][0] = tmp;
    }

    /**
     * MixColumns: multiplica cada columna por la matriz de AES en GF(2^8).
     *
     * La multiplicación en GF(2^8) usa el polinomio irreducible x^8+x^4+x^3+x+1.
     * Matriz aplicada:
     *   [2 3 1 1]
     *   [1 2 3 1]
     *   [1 1 2 3]
     *   [3 1 1 2]
     *
     * Garantiza que un cambio en un solo byte afecte a todos los demás de la columna.
     */
    private static void mixColumns(byte[][] state) {
        for (int c = 0; c < 4; c++) {
            int s0 = state[0][c] & 0xFF, s1 = state[1][c] & 0xFF;
            int s2 = state[2][c] & 0xFF, s3 = state[3][c] & 0xFF;

            state[0][c] = (byte)(mul2(s0) ^ mul3(s1) ^     s2  ^     s3 );
            state[1][c] = (byte)(    s0   ^ mul2(s1) ^ mul3(s2) ^     s3 );
            state[2][c] = (byte)(    s0   ^     s1   ^ mul2(s2) ^ mul3(s3));
            state[3][c] = (byte)(mul3(s0) ^     s1   ^     s2   ^ mul2(s3));
        }
    }

    // XOR del estado con la clave de ronda en el índice dado
    private void addRoundKey(byte[][] state, int ronda) {
        for (int c = 0; c < 4; c++) {
            int word = roundKeys[ronda * 4 + c];
            state[0][c] ^= (word >>> 24) & 0xFF;
            state[1][c] ^= (word >>> 16) & 0xFF;
            state[2][c] ^= (word >>>  8) & 0xFF;
            state[3][c] ^=  word         & 0xFF;
        }
    }

    // ──────────────────────────────────────────────────────────
    //  OPERACIONES DE RONDA — DESCIFRADO
    // ──────────────────────────────────────────────────────────

    private void invSubBytes(byte[][] state) {
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                state[r][c] = sboxInv[state[r][c] & 0xFF];
    }

    // Desplaza cada fila r del estado r posiciones a la DERECHA
    private static void invShiftRows(byte[][] state) {
        byte tmp;

        // Fila 1: desplazar 1 posición derecha
        tmp = state[1][3];
        state[1][3] = state[1][2]; state[1][2] = state[1][1];
        state[1][1] = state[1][0]; state[1][0] = tmp;

        // Fila 2: desplazar 2 posiciones (= intercambiar pares)
        tmp = state[2][0]; state[2][0] = state[2][2]; state[2][2] = tmp;
        tmp = state[2][1]; state[2][1] = state[2][3]; state[2][3] = tmp;

        // Fila 3: desplazar 3 posiciones derecha (= 1 posición izquierda)
        tmp = state[3][0];
        state[3][0] = state[3][1]; state[3][1] = state[3][2];
        state[3][2] = state[3][3]; state[3][3] = tmp;
    }

    /**
     * InvMixColumns: aplica la matriz inversa de MixColumns en GF(2^8).
     * Matriz inversa:
     *   [14 11 13  9]
     *   [ 9 14 11 13]
     *   [13  9 14 11]
     *   [11 13  9 14]
     */
    private static void invMixColumns(byte[][] state) {
        for (int c = 0; c < 4; c++) {
            int s0 = state[0][c] & 0xFF, s1 = state[1][c] & 0xFF;
            int s2 = state[2][c] & 0xFF, s3 = state[3][c] & 0xFF;

            state[0][c] = (byte)(mul14(s0) ^ mul11(s1) ^ mul13(s2) ^ mul9(s3) );
            state[1][c] = (byte)(mul9(s0)  ^ mul14(s1) ^ mul11(s2) ^ mul13(s3));
            state[2][c] = (byte)(mul13(s0) ^ mul9(s1)  ^ mul14(s2) ^ mul11(s3));
            state[3][c] = (byte)(mul11(s0) ^ mul13(s1) ^ mul9(s2)  ^ mul14(s3));
        }
    }

    // ──────────────────────────────────────────────────────────
    //  ARITMÉTICA EN GF(2^8)
    //  Polinomio irreducible: x^8 + x^4 + x^3 + x + 1  (0x11B)
    // ──────────────────────────────────────────────────────────

    // Multiplicación por 2: desplazamiento con reducción modular si hay desbordamiento
    private static int mul2(int a) {
        return ((a << 1) ^ ((a & 0x80) != 0 ? 0x1B : 0x00)) & 0xFF;
    }

    private static int mul3(int a)  { return mul2(a) ^ a; }
    private static int mul4(int a)  { return mul2(mul2(a)); }
    private static int mul8(int a)  { return mul2(mul4(a)); }
    private static int mul9(int a)  { return mul8(a) ^ a; }
    private static int mul11(int a) { return mul8(a) ^ mul2(a) ^ a; }
    private static int mul13(int a) { return mul8(a) ^ mul4(a) ^ a; }
    private static int mul14(int a) { return mul8(a) ^ mul4(a) ^ mul2(a); }

    // ──────────────────────────────────────────────────────────
    //  CIFRADO / DESCIFRADO DE UN BLOQUE DE 16 BYTES
    // ──────────────────────────────────────────────────────────

    private byte[] cifrarBloque(byte[] bloque) {
        byte[][] state = bytesAEstado(bloque);

        addRoundKey(state, 0);

        for (int r = 1; r < NR; r++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, r);
        }

        // Última ronda: sin MixColumns
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, NR);

        return estadoABytes(state);
    }

    private byte[] descifrarBloque(byte[] bloque) {
        byte[][] state = bytesAEstado(bloque);

        addRoundKey(state, NR);

        for (int r = NR - 1; r >= 1; r--) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, r);
            invMixColumns(state);
        }

        // Primera ronda inversa: sin InvMixColumns
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, 0);

        return estadoABytes(state);
    }

    // ──────────────────────────────────────────────────────────
    //  API PÚBLICA
    // ──────────────────────────────────────────────────────────

    /**
     * Cifra un mensaje de longitud arbitraria.
     * Aplica padding PKCS7 para que sea múltiplo de 16 bytes.
     * Soporta cualquier contenido UTF-8 incluyendo ñ y emojis.
     */
    public byte[] cifrar(byte[] plaintext) {
        byte[] datos     = agregarPaddingPKCS7(plaintext);
        byte[] resultado = new byte[datos.length];

        for (int offset = 0; offset < datos.length; offset += BLOCK_SIZE) {
            byte[] bloque  = Arrays.copyOfRange(datos, offset, offset + BLOCK_SIZE);
            byte[] cifrado = cifrarBloque(bloque);
            System.arraycopy(cifrado, 0, resultado, offset, BLOCK_SIZE);
        }

        return resultado;
    }

    /**
     * Descifra y elimina el padding PKCS7.
     * Lanza excepción si el ciphertext o el padding son inválidos.
     */
    public byte[] descifrar(byte[] ciphertext) throws Exception {
        if (ciphertext.length == 0 || ciphertext.length % BLOCK_SIZE != 0) {
            throw new IllegalArgumentException("Longitud de ciphertext inválida.");
        }

        byte[] resultado = new byte[ciphertext.length];

        for (int offset = 0; offset < ciphertext.length; offset += BLOCK_SIZE) {
            byte[] bloque     = Arrays.copyOfRange(ciphertext, offset, offset + BLOCK_SIZE);
            byte[] descifrado = descifrarBloque(bloque);
            System.arraycopy(descifrado, 0, resultado, offset, BLOCK_SIZE);
        }

        return quitarPaddingPKCS7(resultado);
    }

    // ──────────────────────────────────────────────────────────
    //  PADDING PKCS7
    // ──────────────────────────────────────────────────────────

    // Si faltan n bytes para completar el bloque, añade n bytes con valor n.
    // Si el mensaje ya es múltiplo de 16, añade un bloque completo de 16 bytes con valor 16.
    private static byte[] agregarPaddingPKCS7(byte[] datos) {
        int pad      = BLOCK_SIZE - (datos.length % BLOCK_SIZE);
        byte[] result = new byte[datos.length + pad];
        System.arraycopy(datos, 0, result, 0, datos.length);
        Arrays.fill(result, datos.length, result.length, (byte) pad);
        return result;
    }

    // Lee el valor del último byte para saber cuántos bytes quitar y los verifica.
    private static byte[] quitarPaddingPKCS7(byte[] datos) throws Exception {
        int pad = datos[datos.length - 1] & 0xFF;
        if (pad == 0 || pad > BLOCK_SIZE) {
            throw new Exception("Padding PKCS7 inválido.");
        }
        for (int i = datos.length - pad; i < datos.length; i++) {
            if ((datos[i] & 0xFF) != pad) {
                throw new Exception("Padding PKCS7 corrupto.");
            }
        }
        return Arrays.copyOf(datos, datos.length - pad);
    }

    // ──────────────────────────────────────────────────────────
    //  CONVERSIÓN ESTADO ↔ BYTES (orden columna-mayor, estándar AES)
    // ──────────────────────────────────────────────────────────

    private static byte[][] bytesAEstado(byte[] bloque) {
        byte[][] s = new byte[4][4];
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                s[r][c] = bloque[r + 4 * c];
        return s;
    }

    private static byte[] estadoABytes(byte[][] s) {
        byte[] out = new byte[BLOCK_SIZE];
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                out[r + 4 * c] = s[r][c];
        return out;
    }
}