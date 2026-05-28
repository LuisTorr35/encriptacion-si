<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class UserController extends Controller
{
    /** Lista los demas usuarios (excluye al autenticado). */
    public function index(Request $request): JsonResponse
    {
        $users = User::where('id', '!=', $request->user()->id)
            ->orderBy('name')
            ->get(['id', 'name', 'email', 'public_key'])
            ->map(fn (User $u) => [
                'id' => $u->id,
                'name' => $u->name,
                'email' => $u->email,
                'has_key' => (bool) $u->public_key,
            ]);

        return response()->json(['users' => $users]);
    }
}
