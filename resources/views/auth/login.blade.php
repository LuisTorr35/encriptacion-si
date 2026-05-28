<x-guest-layout>
    <h2 class="text-lg font-semibold text-gray-900">Inicia sesión</h2>
    <p class="mb-5 mt-0.5 text-sm text-gray-500">Entra para chatear de forma cifrada.</p>

    <!-- Session Status -->
    <x-auth-session-status class="mb-4" :status="session('status')" />

    <form method="POST" action="{{ route('login') }}" class="space-y-4">
        @csrf

        <!-- Email Address -->
        <div>
            <x-input-label for="email" :value="__('Email')" />
            <x-text-input id="email" class="block mt-1 w-full" type="email" name="email" :value="old('email')" required autofocus autocomplete="username" />
            <x-input-error :messages="$errors->get('email')" class="mt-2" />
        </div>

        <!-- Password -->
        <div>
            <x-input-label for="password" :value="__('Contraseña')" />
            <x-text-input id="password" class="block mt-1 w-full"
                            type="password"
                            name="password"
                            required autocomplete="current-password" />
            <x-input-error :messages="$errors->get('password')" class="mt-2" />
        </div>

        <!-- Remember Me + olvidé contraseña -->
        <div class="flex items-center justify-between">
            <label for="remember_me" class="inline-flex items-center">
                <input id="remember_me" type="checkbox" class="rounded border-gray-300 text-sky-600 shadow-sm focus:ring-sky-500" name="remember">
                <span class="ms-2 text-sm text-gray-600">{{ __('Recordarme') }}</span>
            </label>

            @if (Route::has('password.request'))
                <a class="text-sm text-sky-600 underline hover:text-sky-800 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-sky-500 rounded" href="{{ route('password.request') }}">
                    {{ __('¿Olvidaste tu contraseña?') }}
                </a>
            @endif
        </div>

        <x-primary-button class="w-full justify-center py-2.5 text-sm">
            {{ __('Iniciar sesión') }}
        </x-primary-button>

        <p class="text-center text-sm text-gray-500">
            ¿No tienes cuenta?
            <a href="{{ route('register') }}" class="font-medium text-sky-600 underline hover:text-sky-800">Crear una</a>
        </p>
    </form>
</x-guest-layout>
