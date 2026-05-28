<?php

use App\Http\Controllers\Api\ConversationController;
use App\Http\Controllers\Api\KeyController;
use App\Http\Controllers\Api\MessageController;
use App\Http\Controllers\Api\UserController;
use App\Http\Controllers\ChatController;
use App\Http\Controllers\ProfileController;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

Route::middleware(['auth', 'verified'])->group(function () {
    Route::get('/chat', [ChatController::class, 'index'])->name('chat');
    // El dashboard de Breeze redirige al chat (es la pantalla principal).
    Route::get('/dashboard', fn () => redirect()->route('chat'))->name('dashboard');
});

Route::middleware('auth')->group(function () {
    Route::get('/profile', [ProfileController::class, 'edit'])->name('profile.edit');
    Route::patch('/profile', [ProfileController::class, 'update'])->name('profile.update');
    Route::delete('/profile', [ProfileController::class, 'destroy'])->name('profile.destroy');

    // API del chat — usa la sesion de Breeze (cookie + CSRF), nunca descifra.
    Route::prefix('api')->group(function () {
        Route::post('/keys', [KeyController::class, 'store']);
        Route::get('/users', [UserController::class, 'index']);
        Route::get('/users/{user}/key', [KeyController::class, 'show']);
        Route::get('/conversations', [ConversationController::class, 'index']);
        Route::post('/conversations', [ConversationController::class, 'store']);
        Route::get('/conversations/{conversation}/messages', [MessageController::class, 'index']);
        Route::post('/conversations/{conversation}/messages', [MessageController::class, 'store']);
    });
});

require __DIR__.'/auth.php';
