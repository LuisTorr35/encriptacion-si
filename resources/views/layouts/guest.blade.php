<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta name="csrf-token" content="{{ csrf_token() }}">

        <title>{{ config('app.name', 'Laravel') }}</title>

        <!-- Fonts -->
        <link rel="preconnect" href="https://fonts.bunny.net">
        <link href="https://fonts.bunny.net/css?family=figtree:400,500,600&display=swap" rel="stylesheet" />

        <!-- Scripts -->
        @vite(['resources/css/app.css', 'resources/js/app.js'])
    </head>
    <body class="font-sans text-gray-900 antialiased">
        <div class="min-h-screen flex flex-col justify-center items-center px-4 py-10 bg-gradient-to-b from-sky-50 via-gray-50 to-gray-100">
            <a href="/" class="flex flex-col items-center mb-6 no-underline">
                <span class="flex h-16 w-16 items-center justify-center rounded-2xl bg-sky-500 text-3xl shadow-lg shadow-sky-500/30">🔐</span>
                <h1 class="mt-3 text-2xl font-bold tracking-tight text-gray-900">Chat Encriptado</h1>
                <p class="text-sm text-gray-500">Mensajería cifrada de extremo a extremo</p>
            </a>

            <div class="w-full sm:max-w-md px-6 py-7 sm:px-8 bg-white shadow-xl ring-1 ring-gray-200/70 rounded-2xl">
                {{ $slot }}
            </div>

            <p class="mt-6 max-w-md text-center text-xs text-gray-400">
                🔒 Tus mensajes se cifran en tu navegador. El servidor nunca ve el texto ni tu clave privada.
            </p>
        </div>

        <script>
            // Captura la contrasena en el navegador (login/registro) para poder
            // envolver/recuperar la clave privada E2E entre dispositivos. NUNCA se
            // envia al servidor: solo se usa localmente para derivar la clave (PBKDF2).
            document.addEventListener('submit', function (e) {
                var pw = e.target.querySelector('input[name="password"]');
                if (pw && pw.value) {
                    try { sessionStorage.setItem('e2e.pw', pw.value); } catch (_) {}
                }
            }, true);
        </script>
    </body>
</html>
