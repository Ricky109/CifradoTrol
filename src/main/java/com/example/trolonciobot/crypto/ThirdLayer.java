package com.example.trolonciobot.crypto;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;
 
/**
 * Tercera capa de cifrado — diseño propio basado en red de Feistel.
 *
 * Aplica 8 rondas sobre el ciphertext que salió de AES.
 * Cada ronda divide el bloque en dos mitades y aplica una
 * función de ronda (F) con las siguientes propiedades:
 *
 *   - Subclave propia: SHA-256(Clave_L3 || ronda)
 *   - Orden de operaciones variable: 6 permutaciones distintas
 *     de XOR, rotación de bits e intercambio de pares
 *
 * Estructura Feistel por ronda:
 *   nuevo_R = L XOR F(R, SubClave[i])
 *   nuevo_L = R
 *
 * Descifrado: mismas subclaves, rondas en orden inverso.
 * F no necesita ser invertible — la estructura Feistel
 * garantiza la reversibilidad por construcción.
 *
 * Longitud impar: el último byte se procesa por separado
 * con un XOR de la última subclave (Opción B).
 */
public class ThirdLayer {
 
    private static final int RONDAS = 8;
 
    // 6 permutaciones de las 3 operaciones (0=XOR, 1=Rotar, 2=Swap)
    // Distribuidas en 8 rondas ciclando cada 6
    private static final int[][] ORDENES = {
        {0, 1, 2},  // Ronda 0, 6: XOR → Rotar → Swap
        {1, 2, 0},  // Ronda 1, 7: Rotar → Swap → XOR
        {2, 0, 1},  // Ronda 2:    Swap → XOR → Rotar
        {0, 2, 1},  // Ronda 3:    XOR → Swap → Rotar
        {1, 0, 2},  // Ronda 4:    Rotar → XOR → Swap
        {2, 1, 0}   // Ronda 5:    Swap → Rotar → XOR
    };
 
    // ──────────────────────────────────────────────────────────
    //  GENERACIÓN DE CLAVES
    // ──────────────────────────────────────────────────────────
 
    private static byte[] generarClaveL3(byte[] claveAES, long timestamp) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        sha256.update(claveAES);
        sha256.update(ByteBuffer.allocate(8).putLong(timestamp).array());
        return sha256.digest();
    }
 
    /**
     * Genera 8 subclaves independientes a partir de Clave_L3.
     * SubClave[i] = SHA-256(Clave_L3 || byte(i))
     * Cada ronda opera con una clave completamente distinta.
     */
    private static byte[][] generarSubclaves(byte[] claveL3) throws Exception {
        byte[][] subclaves = new byte[RONDAS][];
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        for (int i = 0; i < RONDAS; i++) {
            sha256.reset();
            sha256.update(claveL3);
            sha256.update((byte) i);
            subclaves[i] = sha256.digest(); // 32 bytes por subclave
        }
        return subclaves;
    }
 
    // ──────────────────────────────────────────────────────────
    //  CIFRADO
    // ──────────────────────────────────────────────────────────
 
    public static byte[] cifrar(byte[] datos, byte[] claveAES, long timestamp) throws Exception {
        byte[]   claveL3   = generarClaveL3(claveAES, timestamp);
        byte[][] subclaves = generarSubclaves(claveL3);
 
        // Opción B: separar el último byte si la longitud es impar
        boolean impar     = (datos.length % 2) != 0;
        byte    ultByte   = impar ? datos[datos.length - 1] : 0;
        byte[]  bloque    = impar
            ? Arrays.copyOf(datos, datos.length - 1)
            : datos.clone();
 
        // Dividir en dos mitades iguales
        int    mitad = bloque.length / 2;
        byte[] L     = Arrays.copyOfRange(bloque, 0, mitad);
        byte[] R     = Arrays.copyOfRange(bloque, mitad, bloque.length);
 
        // 8 rondas Feistel
        for (int i = 0; i < RONDAS; i++) {
            byte[] fResult = funcionRonda(R, subclaves[i], ORDENES[i % 6]);
            byte[] nuevoR  = xorArrays(L, fResult);
            L = R;
            R = nuevoR;
        }
 
        // Ensamblar resultado
        byte[] resultado = new byte[datos.length];
        System.arraycopy(L, 0, resultado, 0, mitad);
        System.arraycopy(R, 0, resultado, mitad, R.length);
 
        // Último byte separado: XOR con el primer byte de la última subclave
        if (impar) {
            resultado[datos.length - 1] = (byte)(ultByte ^ subclaves[RONDAS - 1][0]);
        }
 
        return resultado;
    }
 
    // ──────────────────────────────────────────────────────────
    //  DESCIFRADO — rondas en orden inverso, mismas subclaves
    // ──────────────────────────────────────────────────────────
 
    public static byte[] descifrar(byte[] datos, byte[] claveAES, long timestamp) throws Exception {
        byte[]   claveL3   = generarClaveL3(claveAES, timestamp);
        byte[][] subclaves = generarSubclaves(claveL3);
 
        boolean impar   = (datos.length % 2) != 0;
        byte    ultByte = impar ? datos[datos.length - 1] : 0;
        byte[]  bloque  = impar
            ? Arrays.copyOf(datos, datos.length - 1)
            : datos.clone();
 
        int    mitad = bloque.length / 2;
        byte[] L     = Arrays.copyOfRange(bloque, 0, mitad);
        byte[] R     = Arrays.copyOfRange(bloque, mitad, bloque.length);
 
        // 8 rondas en orden inverso
        // Prueba matemática: si cifrado hizo (L,R) → (R, L XOR F(R,K))
        // entonces descifrado con (L',R'): F(L',K) = F(R,K)
        // nuevoL = R' XOR F(L',K) = (L XOR F(R,K)) XOR F(R,K) = L ✓
        for (int i = RONDAS - 1; i >= 0; i--) {
            byte[] fResult = funcionRonda(L, subclaves[i], ORDENES[i % 6]);
            byte[] nuevoL  = xorArrays(R, fResult);
            R = L;
            L = nuevoL;
        }
 
        byte[] resultado = new byte[datos.length];
        System.arraycopy(L, 0, resultado, 0, mitad);
        System.arraycopy(R, 0, resultado, mitad, R.length);
 
        // Último byte: misma operación XOR (es su propio inverso)
        if (impar) {
            resultado[datos.length - 1] = (byte)(ultByte ^ subclaves[RONDAS - 1][0]);
        }
 
        return resultado;
    }
 
    // ──────────────────────────────────────────────────────────
    //  FUNCIÓN DE RONDA F
    // ──────────────────────────────────────────────────────────
 
    /**
     * Aplica las 3 operaciones en el orden indicado por ORDENES[ronda % 6].
     * El resultado tiene siempre la misma longitud que la entrada.
     * F no necesita ser invertible — Feistel se encarga de la reversibilidad.
     */
    private static byte[] funcionRonda(byte[] datos, byte[] subclave, int[] orden) {
        byte[] resultado = datos.clone();
        for (int op : orden) {
            switch (op) {
                case 0: resultado = aplicarXOR(resultado, subclave);      break;
                case 1: resultado = aplicarRotacion(resultado, subclave); break;
                case 2: resultado = aplicarSwap(resultado);               break;
            }
        }
        return resultado;
    }
 
    // ──────────────────────────────────────────────────────────
    //  OPERACIONES
    // ──────────────────────────────────────────────────────────
 
    // XOR byte a byte con la subclave (cicla si el bloque supera 32 bytes)
    private static byte[] aplicarXOR(byte[] datos, byte[] subclave) {
        byte[] resultado = new byte[datos.length];
        for (int i = 0; i < datos.length; i++) {
            resultado[i] = (byte)(datos[i] ^ subclave[i % 32]);
        }
        return resultado;
    }
 
    // Rotación de bits de cada byte, dirección y cantidad determinadas por subclave
    private static byte[] aplicarRotacion(byte[] datos, byte[] subclave) {
        byte[] resultado = new byte[datos.length];
        for (int i = 0; i < datos.length; i++) {
            resultado[i] = rotarBits(datos[i], subclave, i);
        }
        return resultado;
    }
 
    // Intercambio de bytes adyacentes en pares
    private static byte[] aplicarSwap(byte[] datos) {
        byte[] resultado = datos.clone();
        for (int i = 0; i + 1 < resultado.length; i += 2) {
            byte tmp         = resultado[i];
            resultado[i]     = resultado[i + 1];
            resultado[i + 1] = tmp;
        }
        return resultado;
    }
 
    /**
     * Rota los 8 bits del byte b.
     * N = (subclave[i % 32] mod 7) + 1  → entre 1 y 7 posiciones
     * Dirección: bit (i+1) de subclave == 0 → izquierda, == 1 → derecha
     */
    private static byte rotarBits(byte b, byte[] subclave, int i) {
        int n   = (subclave[i % 32] & 0xFF) % 7 + 1;
        int val = b & 0xFF;
        int dir = getBit(subclave, i + 1);
        if (dir == 0) {
            return (byte)(((val << n) | (val >>> (8 - n))) & 0xFF);
        } else {
            return (byte)(((val >>> n) | (val << (8 - n))) & 0xFF);
        }
    }
 
    // ──────────────────────────────────────────────────────────
    //  UTILIDADES
    // ──────────────────────────────────────────────────────────
 
    // XOR elemento a elemento entre dos arrays (b cicla si es más corto que a)
    private static byte[] xorArrays(byte[] a, byte[] b) {
        byte[] resultado = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            resultado[i] = (byte)(a[i] ^ b[i % b.length]);
        }
        return resultado;
    }
 
    // Extrae el bit en posición i del array de bytes
    private static int getBit(byte[] bytes, int i) {
        int byteIdx = (i / 8) % bytes.length;
        int bitIdx  = 7 - (i % 8);
        return (bytes[byteIdx] >> bitIdx) & 1;
    }
}