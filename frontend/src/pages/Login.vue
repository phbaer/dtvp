<script setup lang="ts">
import { login } from '../lib/api'
</script>

<template>
  <div class="flex flex-col items-center justify-center min-h-screen bg-gray-950 text-white">
    <div class="p-8 bg-gray-800 rounded-lg shadow-lg border border-gray-700 text-center max-w-md w-full">
      <h1 class="text-3xl font-bold mb-2 text-blue-500">DTVP</h1>
      <p class="text-gray-400 mb-8">Sign in to assess vulnerabilities</p>
      
      <button 
          @click="login"
          class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-4 rounded transition-colors cursor-pointer"
      >
          Sign in with SSO
      </button>
    </div>
  </div>
</template>
