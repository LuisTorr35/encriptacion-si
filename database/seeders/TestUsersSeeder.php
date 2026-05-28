<?php

namespace Database\Seeders;

use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;

class TestUsersSeeder extends Seeder
{
    /** Dos usuarios de prueba para la demo E2E. */
    public function run(): void
    {
        foreach ([
            ['name' => 'Ana', 'email' => 'ana@test.com'],
            ['name' => 'Beto', 'email' => 'beto@test.com'],
        ] as $u) {
            User::updateOrCreate(
                ['email' => $u['email']],
                [
                    'name' => $u['name'],
                    'password' => Hash::make('password'),
                    'email_verified_at' => now(),
                ],
            );
        }
    }
}
