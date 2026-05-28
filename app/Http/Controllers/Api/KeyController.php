<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class KeyController extends Controller
{
    /** Sube/actualiza la clave publica RSA del usuario autenticado. */
    public function store(Request $request): JsonResponse
    {
        $data = $request->validate([
            'public_key' => ['required', 'string', 'max:20000'],
        ]);

        // Debe ser un JSON con campos n y e (clave publica exportada).
        $decoded = json_decode($data['public_key'], true);
        if (! is_array($decoded) || empty($decoded['n']) || empty($decoded['e'])) {
            return response()->json(['message' => 'Formato de clave publica invalido.'], 422);
        }

        $user = $request->user();
        $user->public_key = $data['public_key'];
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
