<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('messages', function (Blueprint $table) {
            $table->id();
            $table->foreignId('conversation_id')->constrained()->cascadeOnDelete();
            $table->foreignId('sender_id')->constrained('users')->cascadeOnDelete();

            // Sobre cifrado E2E (todo Base64). El servidor jamas descifra.
            $table->integer('v')->default(1);          // version del sobre
            $table->text('enc_key_sender');             // K envuelta con la publica del emisor
            $table->text('enc_key_recipient');          // K envuelta con la publica del receptor
            $table->text('ciphertext');                 // C (AES-256-CTR)
            $table->text('mac');                        // T (HMAC-SHA256)
            $table->text('nonce');                      // nonce/IV del CTR
            $table->text('signature')->nullable();      // opcional (RSA-PSS)

            $table->timestamps();

            $table->index(['conversation_id', 'id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('messages');
    }
};
