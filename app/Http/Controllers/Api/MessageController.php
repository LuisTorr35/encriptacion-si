<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Conversation;
use App\Models\Message;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class MessageController extends Controller
{
    /** Mensajes de la conversacion (polling: solo los posteriores a ?after=). */
    public function index(Request $request, Conversation $conversation): JsonResponse
    {
        $this->authorizeMember($request, $conversation);

        $after = (int) $request->query('after', 0);

        $messages = $conversation->messages()
            ->where('id', '>', $after)
            ->orderBy('id')
            ->limit(200)
            ->get()
            ->map(fn (Message $m) => $this->present($m, $request->user()->id));

        return response()->json(['messages' => $messages]);
    }

    /** Recibe un sobre cifrado y lo guarda SIN descifrar. */
    public function store(Request $request, Conversation $conversation): JsonResponse
    {
        $this->authorizeMember($request, $conversation);

        $data = $request->validate([
            'v' => ['nullable', 'integer'],
            'enc_key_sender' => ['required', 'string', 'max:20000'],
            'enc_key_recipient' => ['required', 'string', 'max:20000'],
            'ciphertext' => ['required', 'string'],
            'mac' => ['required', 'string', 'max:200'],
            'nonce' => ['required', 'string', 'max:200'],
            'signature' => ['nullable', 'string', 'max:20000'],
        ]);

        $message = $conversation->messages()->create([
            'sender_id' => $request->user()->id,
            'v' => $data['v'] ?? 1,
            'enc_key_sender' => $data['enc_key_sender'],
            'enc_key_recipient' => $data['enc_key_recipient'],
            'ciphertext' => $data['ciphertext'],
            'mac' => $data['mac'],
            'nonce' => $data['nonce'],
            'signature' => $data['signature'] ?? null,
        ]);

        return response()->json(['message' => $this->present($message, $request->user()->id)], 201);
    }

    private function authorizeMember(Request $request, Conversation $conversation): void
    {
        abort_unless(
            $conversation->users()->where('users.id', $request->user()->id)->exists(),
            403,
            'No perteneces a esta conversacion.'
        );
    }

    private function present(Message $m, int $currentUserId): array
    {
        return [
            'id' => $m->id,
            'sender_id' => $m->sender_id,
            'mine' => $m->sender_id === $currentUserId,
            'v' => $m->v,
            'enc_key_sender' => $m->enc_key_sender,
            'enc_key_recipient' => $m->enc_key_recipient,
            'ciphertext' => $m->ciphertext,
            'mac' => $m->mac,
            'nonce' => $m->nonce,
            'signature' => $m->signature,
            'created_at' => $m->created_at->toIso8601String(),
        ];
    }
}
