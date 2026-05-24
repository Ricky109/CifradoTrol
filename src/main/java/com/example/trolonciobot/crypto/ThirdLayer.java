package com.example.trolonciobot.crypto;

import java.nio.ByteBuffer;
import java.security.MessageDigest;

/**
 * Tercera capa de cifrado — diseño propio.
 *
 * Aplica tres operaciones en secuencia sobre cada byte del ciphertext
 * que salió de AES. Al ser un flujo único sin condiciones, funciona
 * correctamente con cualquier contenido: texto, ñ, emojis, etc.
 *
 * La clave (Clave_L3) se genera como SHA-256(claveAES || timestamp),
 * garantizando que dos mensajes idénticos producen salidas distintas.
 *
 * Flujo de CIFRADO (en orden):
 *   1. XOR   — byte[i] XOR Clave_L3[i mod 32]
 *   2. ROTAR — rotar bits según Clave_L3[i mod 32]
 *   3. SWAP  — intercambiar byte[i] con byte[i+1] en posiciones pares
 *
 * Flujo de DESCIFRADO (en orden inverso):
 *   1. SWAP  inverso — misma operación (es su propio inverso)
 *   2. ROTAR inverso — rotar en dirección contraria
 *   3. XOR   inverso — misma operación (es su propio inverso)
 */
public class ThirdLayer {

    private static byte[] generarClaveL3(byte[] claveAES, long timestamp) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        sha256.update(claveAES);
        sha256.update(ByteBuffer.allocate(8).putLong(timestamp).array());
        return sha256.digest();
    }

    // ──────────────────────────────────────────────────────────
    //  CIFRADO
    // ──────────────────────────────────────────────────────────

    public static byte[] cifrar(byte[] datos, byte[] claveAES, long timestamp) throws Exception {
        byte[] claveL3   = generarClaveL3(claveAES, timestamp);
        byte[] resultado = datos.clone();
        int    len       = resultado.length;

        // Paso 1: XOR con flujo de clave
        for (int i = 0; i < len; i++) {
            resultado[i] = (byte) (resultado[i] ^ claveL3[i % 32]);
        }

        // Paso 2: rotar bits de cada byte según la clave
        for (int i = 0; i < len; i++) {
            resultado[i] = rotarIzquierda(resultado[i], claveL3[i % 32]);
        }

        // Paso 3: swap de bytes adyacentes en posiciones pares
        for (int i = 0; i + 1 < len; i += 2) {
            byte tmp         = resultado[i];
            resultado[i]     = resultado[i + 1];
            resultado[i + 1] = tmp;
        }

        return resultado;
    }

    // ──────────────────────────────────────────────────────────
    //  DESCIFRADO (pasos en orden inverso)
    // ──────────────────────────────────────────────────────────

    public static byte[] descifrar(byte[] datos, byte[] claveAES, long timestamp) throws Exception {
        byte[] claveL3   = generarClaveL3(claveAES, timestamp);
        byte[] resultado = datos.clone();
        int    len       = resultado.length;

        // Paso 3 inverso: swap (es su propio inverso)
        for (int i = 0; i + 1 < len; i += 2) {
            byte tmp         = resultado[i];
            resultado[i]     = resultado[i + 1];
            resultado[i + 1] = tmp;
        }

        // Paso 2 inverso: rotar en dirección contraria
        for (int i = 0; i < len; i++) {
            resultado[i] = rotarDerecha(resultado[i], claveL3[i % 32]);
        }

        // Paso 1 inverso: XOR (es su propio inverso)
        for (int i = 0; i < len; i++) {
            resultado[i] = (byte) (resultado[i] ^ claveL3[i % 32]);
        }

        return resultado;
    }

    // ──────────────────────────────────────────────────────────
    //  ROTACIÓN DE BITS
    // ──────────────────────────────────────────────────────────

    /**
     * Rota los 8 bits del byte b hacia la izquierda N posiciones.
     * N se deriva de la clave: (claveL3[i] mod 7) + 1 → entre 1 y 7.
     * Nunca rota 0 ni 8 posiciones (serían no-ops).
     */
    private static byte rotarIzquierda(byte b, byte claveB) {
        int n   = (claveB & 0xFF) % 7 + 1;
        int val = b & 0xFF;
        return (byte) (((val << n) | (val >>> (8 - n))) & 0xFF);
    }

    /**
     * Rota los 8 bits del byte b hacia la derecha N posiciones.
     * Invierte exactamente rotarIzquierda con el mismo N.
     */
    private static byte rotarDerecha(byte b, byte claveB) {
        int n   = (claveB & 0xFF) % 7 + 1;
        int val = b & 0xFF;
        return (byte) (((val >>> n) | (val << (8 - n))) & 0xFF);
    }
}