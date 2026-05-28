<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class KeyController extends Controller
{
    /**
     * Sube/actualiza la clave publica RSA del usuario y, opcionalmente, su clave
     * privada CIFRADA (blob PBKDF2+AES+HMAC) para recuperarla en otros dispositivos.
     * El servidor nunca ve la clave privada en claro ni la contrasena.
     */
    public function store(Request $request): JsonResponse
    {
        $data = $request->validate([
            'public_key' => ['required', 'string', 'max:20000'],
            'wrapped_private_key' => ['nullable', 'string', 'max:50000'],
        ]);

        // Debe ser un JSON con campos n y e (clave publica exportada).
        $decoded = json_decode($data['public_key'], true);
        if (! is_array($decoded) || empty($decoded['n']) || empty($decoded['e'])) {
            return response()->json(['message' => 'Formato de clave publica invalido.'], 422);
        }

        $user = $request->user();
        $user->public_key = $data['public_key'];

        // Blob de la clave privada cifrada (opcional): validar su forma minima.
        if (! empty($data['wrapped_private_key'])) {
            $blob = json_decode($data['wrapped_private_key'], true);
            if (! is_array($blob) || empty($blob['salt']) || empty($blob['nonce'])
                || empty($blob['ciphertext']) || empty($blob['mac'])) {
                return response()->json(['message' => 'Formato de clave privada cifrada invalido.'], 422);
            }
            $user->wrapped_private_key = $data['wrapped_private_key'];
        }

        $user->save();

        return response()->json(['ok' => true]);
    }

    /** Devuelve la clave publica de un usuario (para cifrarle mensajes). */
    public function show(User $user): JsonResponse
    {
        if (! $user->public_key) {
            return response()->json(['message' => 'El usuario aun no tiene clave publica.'], 404);
        }

        return response()->json([
            'user_id' => $user->id,
            'public_key' => $user->public_key,
        ]);
    }
}
