package com.example.trolonciobot.storage;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.io.*;
import java.lang.reflect.Type;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Gestiona la persistencia de usuarios y sesiones en un archivo JSON.
 *
 * Almacena SOLO:
 *   - Datos de registro: nombre, chat_id, clave publica RSA (n, e)
 *   - Estado de sesiones activas: quien habla con quien
 *   - Solicitudes de sesion pendientes con timeout
 *
 * NUNCA almacena:
 *   - PINs de usuarios
 *   - Claves AES de sesion
 *   - Claves privadas RSA
 *   - Contenido de mensajes
 */
public class SessionStorage {

    private static final String ARCHIVO        = "datos.json";
    private static final Gson   GSON           = new GsonBuilder().setPrettyPrinting().create();
    private static final long   TIMEOUT_SESION = 60_000; // 60 segundos

    private final Map<Long, Usuario> usuarios = new ConcurrentHashMap<>();
    private final Map<Long, SolicitudSesion> solicitudesPendientes = new ConcurrentHashMap<>();

    // ──────────────────────────────────────────────────────────
    //  MODELO DE DATOS
    // ──────────────────────────────────────────────────────────

    public static class Usuario {
        public long    chatId;
        public String  nombre;
        public String  clavePublicaN;
        public String  clavePublicaE;
        public Long    contactoActivo;
        public boolean registrado;

        public Usuario(long chatId) {
            this.chatId     = chatId;
            this.registrado = false;
        }
    }

    public static class SolicitudSesion {
        public long   solicitanteId;
        public long   receptorId;
        public String sessionId;
        public long   timestamp;
        public String pinHashSolicitante; // SHA-256 del PIN, nunca el PIN en texto plano

        public SolicitudSesion(long solicitanteId, long receptorId,
                               String sessionId, String pinHashSolicitante) {
            this.solicitanteId      = solicitanteId;
            this.receptorId         = receptorId;
            this.sessionId          = sessionId;
            this.timestamp          = System.currentTimeMillis();
            this.pinHashSolicitante = pinHashSolicitante;
        }

        public boolean expirado() {
            return System.currentTimeMillis() - timestamp > TIMEOUT_SESION;
        }
    }

    // ──────────────────────────────────────────────────────────
    //  CARGA Y GUARDADO
    // ──────────────────────────────────────────────────────────

    public SessionStorage() {
        cargar();
    }

    private void cargar() {
        File archivo = new File(ARCHIVO);
        if (!archivo.exists()) return;
        try (Reader reader = new FileReader(archivo)) {
            Type tipo = new TypeToken<Map<Long, Usuario>>(){}.getType();
            Map<Long, Usuario> cargado = GSON.fromJson(reader, tipo);
            if (cargado != null) usuarios.putAll(cargado);
        } catch (Exception e) {
            System.err.println("Error cargando datos: " + e.getMessage());
        }
    }

    public synchronized void guardar() {
        try (Writer writer = new FileWriter(ARCHIVO)) {
            GSON.toJson(usuarios, writer);
        } catch (Exception e) {
            System.err.println("Error guardando datos: " + e.getMessage());
        }
    }

    // ──────────────────────────────────────────────────────────
    //  GESTIÓN DE USUARIOS
    // ──────────────────────────────────────────────────────────

    public Usuario obtenerOCrear(long chatId) {
        return usuarios.computeIfAbsent(chatId, Usuario::new);
    }

    public Usuario obtener(long chatId) {
        return usuarios.get(chatId);
    }

    public Usuario buscarPorNombre(String nombre) {
        return usuarios.values().stream()
            .filter(u -> u.nombre != null && u.nombre.equalsIgnoreCase(nombre))
            .findFirst()
            .orElse(null);
    }

    public boolean estaRegistrado(long chatId) {
        Usuario u = usuarios.get(chatId);
        return u != null && u.registrado;
    }

    public List<Usuario> obtenerTodos() {
        return new ArrayList<>(usuarios.values());
    }

    // ──────────────────────────────────────────────────────────
    //  GESTIÓN DE SOLICITUDES DE SESIÓN
    // ──────────────────────────────────────────────────────────

    public void crearSolicitud(long solicitanteId, long receptorId,
                               String sessionId, String pinHashSolicitante) {
        solicitudesPendientes.put(
            solicitanteId,
            new SolicitudSesion(solicitanteId, receptorId, sessionId, pinHashSolicitante)
        );
    }

    public SolicitudSesion obtenerSolicitudParaReceptor(long receptorId) {
        return solicitudesPendientes.values().stream()
            .filter(s -> s.receptorId == receptorId)
            .findFirst()
            .map(s -> {
                if (s.expirado()) {
                    solicitudesPendientes.remove(s.solicitanteId);
                    return null;
                }
                return s;
            })
            .orElse(null);
    }

    public SolicitudSesion obtenerSolicitudDeSolicitante(long solicitanteId) {
        return solicitudesPendientes.get(solicitanteId);
    }

    public void eliminarSolicitud(long solicitanteId) {
        solicitudesPendientes.remove(solicitanteId);
    }

    public boolean tieneSolicitudPendiente(long solicitanteId) {
        SolicitudSesion s = solicitudesPendientes.get(solicitanteId);
        if (s == null) return false;
        if (s.expirado()) {
            solicitudesPendientes.remove(solicitanteId);
            return false;
        }
        return true;
    }
}