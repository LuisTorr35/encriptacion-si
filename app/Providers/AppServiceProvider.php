<?php

namespace App\Providers;

use Illuminate\Support\Facades\URL;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // Detras del proxy TLS (puerto 8443) las URLs deben ser https para evitar
        // "mixed content". En acceso directo por http (php artisan serve) se dejan
        // en http, para que el CSS/JS cargue bien. FORCE_HTTPS=true fuerza siempre.
        if (env('FORCE_HTTPS', false) || request()->getPort() === 8443) {
            URL::forceScheme('https');
        }
    }
}
