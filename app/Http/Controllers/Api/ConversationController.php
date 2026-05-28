<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Conversation;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class ConversationController extends Controller
{
    /** Mis conversaciones, con el otro participante y la hora del ultimo mensaje. */
    public function index(Request $request): JsonResponse
    {
        $user = $request->user();

        $conversations = $user->conversations()
            ->with(['users:id,name,email,public_key'])
            ->withMax('messages', 'created_at')
            ->get()
            ->map(fn (Conversation $c) => $this->present($c, $user))
            ->sortByDesc(fn ($c) => $c['last_message_at'] ?? '')
            ->values();

        return response()->json(['conversations' => $conversations]);
    }

    /** Crea o recupera la conversacion 1-a-1 con otro usuario. */
    public function store(Request $request): JsonResponse
    {
        $data = $request->validate([
            'user_id' => ['required', 'integer', 'exists:users,id'],
        ]);

        $me = $request->user();
        if ((int) $data['user_id'] === $me->id) {
            return response()->json(['message' => 'No puedes conversar contigo mismo.'], 422);
        }

        $other = User::findOrFail($data['user_id']);

        // Buscar conversacion existente que contenga exactamente a ambos.
        $existing = $me->conversations()
            ->whereHas('users', fn ($q) => $q->where('users.id', $other->id))
            ->withCount('users')
            ->get()
            ->firstWhere('users_count', 2);

        if ($existing) {
            $existing->load(['users:id,name,email,public_key']);
            return response()->json(['conversation' => $this->present($existing, $me)]);
        }

        $conversation = Conversation::create();
        $conversation->users()->attach([$me->id, $other->id]);
        $conversation->load(['users:id,name,email,public_key']);

        return response()->json(['conversation' => $this->present($conversation, $me)], 201);
    }

    private function present(Conversation $c, User $me): array
    {
        $other = $c->otherParticipant($me);

        return [
            'id' => $c->id,
            'last_message_at' => $c->messages_max_created_at ?? null,
            'other' => $other ? [
                'id' => $other->id,
                'name' => $other->name,
                'email' => $other->email,
                'public_key' => $other->public_key,
                'has_key' => (bool) $other->public_key,
            ] : null,
        ];
    }
}
