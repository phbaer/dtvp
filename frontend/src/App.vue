<script setup lang="ts">
// Lucide icons not directly importable as components in global scope without setup
// But we can use them in specific components.
// Here we just use text.
</script>

<template>
  <div class="min-h-screen bg-gray-900 text-white font-sans w-full">
    <template v-if="$route.path !== '/login'">
        <header class="p-4 border-b border-gray-700 flex justify-between items-center bg-gray-800">
        <h1 class="text-xl font-bold text-blue-400">DTVP</h1>
        <div class="text-sm text-gray-400">Dependency Track Vulnerability Processor</div>
        </header>
        <main class="p-8 max-w-7xl mx-auto w-full">
            <router-view></router-view>
        </main>
    </template>
    <router-view v-else></router-view>
  </div>
</template>
