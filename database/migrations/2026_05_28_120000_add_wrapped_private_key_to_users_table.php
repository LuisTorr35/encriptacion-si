<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table) {
            // Clave privada RSA CIFRADA con la contrasena del usuario (PBKDF2+AES+HMAC).
            // El servidor solo guarda este blob; nunca ve la clave en claro ni la contrasena.
            // Permite recuperar la clave en cualquier dispositivo (multi-dispositivo).
            $table->text('wrapped_private_key')->nullable()->after('public_key');
        });
    }

    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn('wrapped_private_key');
        });
    }
};
