<!DOCTYPE html>
<html lang="es" class="h-full">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>Chat Encriptado · {{ $me['name'] }}</title>
    @vite(['resources/css/app.css', 'resources/js/chat.js'])
</head>
<body class="h-full bg-gray-50 font-sans antialiased">
    <div class="app-shell flex flex-col">
        {{-- Barra superior --}}
        <header class="flex items-center justify-between gap-2 border-b border-gray-200 bg-white px-3 py-2.5 sm:px-4">
            <div class="flex min-w-0 items-center gap-2">
                <span class="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-sky-500 text-base shadow-sm shadow-sky-500/30">🔐</span>
                <span class="truncate font-semibold text-gray-900">Chat Encriptado</span>
                <span id="status" class="ml-1 hidden truncate text-xs text-emerald-600 sm:ml-3 sm:inline">conectando…</span>
            </div>
            <div class="flex shrink-0 items-center gap-2 sm:gap-3">
                <span class="hidden text-sm text-gray-600 sm:inline">{{ $me['name'] }}</span>
                <form method="POST" action="{{ route('logout') }}" onsubmit="try { sessionStorage.removeItem('e2e.pw'); } catch (e) {}">
                    @csrf
                    <button type="submit" class="rounded-md px-2.5 py-1 text-sm text-gray-500 hover:bg-gray-100 hover:text-gray-800">
                        Salir
                    </button>
                </form>
            </div>
        </header>

        <div id="layout" data-view="contacts" class="flex min-h-0 flex-1">
            {{-- Panel izquierdo: contactos / conversaciones --}}
            <aside id="sidebar" class="flex w-full shrink-0 flex-col border-r border-gray-200 bg-white md:w-72">
                <div class="border-b border-gray-100 px-4 py-3">
                    <h2 class="text-sm font-semibold uppercase tracking-wide text-gray-400">Contactos</h2>
                </div>
                <div id="contacts" class="flex-1 overflow-y-auto">
                    <p class="px-4 py-6 text-sm text-gray-400">Cargando…</p>
                </div>
            </aside>

            {{-- Panel derecho: hilo de conversacion --}}
            <main id="main-panel" class="flex min-w-0 flex-1 flex-col bg-gray-100">
                {{-- Estado vacio --}}
                <div id="empty-state" class="flex flex-1 flex-col items-center justify-center text-center text-gray-400">
                    <div class="mb-3 text-5xl">💬</div>
                    <p class="text-sm">Selecciona un contacto para iniciar una conversacion cifrada.</p>
                </div>

                {{-- Conversacion activa --}}
                <div id="chat-panel" class="hidden min-h-0 flex-1 flex-col">
                    <div class="flex items-center gap-3 border-b border-gray-200 bg-white px-3 py-2.5 sm:px-4">
                        <button id="thread-back" type="button" aria-label="Volver a contactos"
                                class="-ml-1 flex h-9 w-9 shrink-0 items-center justify-center rounded-full text-gray-500 hover:bg-gray-100 md:hidden">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M15 18l-6-6 6-6"/>
                            </svg>
                        </button>
                        <div id="thread-avatar" class="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-sky-500 text-sm font-semibold text-white"></div>
                        <div class="min-w-0">
                            <div id="thread-name" class="truncate font-medium text-gray-900"></div>
                            <div id="thread-sub" class="truncate text-xs text-emerald-600"></div>
                        </div>
                    </div>

                    <div id="thread-scroll" class="min-h-0 flex-1 overflow-y-auto px-4 py-4">
                        <div id="thread" class="mx-auto flex max-w-3xl flex-col gap-2"></div>
                    </div>

                    <form id="composer" class="flex items-end gap-2 border-t border-gray-200 bg-white px-4 py-3">
                        <textarea id="composer-input" rows="1"
                                  class="max-h-40 flex-1 resize-none rounded-2xl border-gray-300 px-4 py-2 text-[15px] focus:border-sky-500 focus:ring-sky-500"
                                  placeholder="Escribe un mensaje cifrado…"></textarea>
                        <button id="composer-send" type="submit"
                                class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-sky-500 text-white transition hover:bg-sky-600 disabled:opacity-40">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 24 24" fill="currentColor">
                                <path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/>
                            </svg>
                        </button>
                    </form>
                </div>
            </main>
        </div>
    </div>

    <script>
        window.__CHAT__ = {
            me: @json($me),
            csrf: document.querySelector('meta[name="csrf-token"]').content,
        };
    </script>
</body>
</html>
