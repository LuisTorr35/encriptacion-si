<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\View\View;

class ChatController extends Controller
{
    /** Renderiza la app de chat. La criptografia ocurre integramente en el cliente. */
    public function index(Request $request): View
    {
        $user = $request->user();

        return view('chat.index', [
            'me' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'has_key' => (bool) $user->public_key,
                'public_key' => $user->public_key,
            ],
        ]);
    }
}
