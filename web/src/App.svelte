<script lang="ts">
  import ClientPage from "./lib/ClientPage.svelte";
  import ServerPage from "./lib/ServerPage.svelte";

  type Page = "client" | "server";
  let currentPage: Page = "client";

  // Simple hash-based routing
  const updatePage = () => {
    const hash = window.location.hash.slice(1);
    if (hash === "server") {
      currentPage = "server";
    } else {
      currentPage = "client";
    }
  };

  // Initialize on load
  updatePage();
  window.addEventListener("hashchange", updatePage);

  const navigate = (page: Page) => {
    window.location.hash = page;
  };
</script>

<main>
  <nav>
    <h1>WebRTC Demo</h1>
    <div class="nav-links">
      <button
        class:active={currentPage === "client"}
        on:click={() => navigate("client")}
      >
        Client Mode
      </button>
      <button
        class:active={currentPage === "server"}
        on:click={() => navigate("server")}
      >
        Server Mode
      </button>
    </div>
    <p class="hint">
      {#if currentPage === "client"}
        Use with: <code>make run</code> (Python as server)
      {:else}
        Use with: <code>make client</code> (Python as client)
      {/if}
    </p>
  </nav>

  {#key currentPage}
    {#if currentPage === "client"}
      <ClientPage />
    {:else}
      <ServerPage />
    {/if}
  {/key}
</main>

<style>
  main {
    max-width: 800px;
    margin: 0 auto;
    padding: 1rem;
  }

  nav {
    border-bottom: 1px solid #ccc;
    padding-bottom: 1rem;
    margin-bottom: 1rem;
  }

  h1 {
    margin: 0 0 1rem 0;
  }

  .nav-links {
    display: flex;
    gap: 0.5rem;
  }

  .nav-links button {
    padding: 0.5rem 1rem;
    border: 1px solid #ccc;
    background: #f5f5f5;
    cursor: pointer;
    font-size: 1rem;
  }

  .nav-links button:hover {
    background: #e5e5e5;
  }

  .nav-links button.active {
    background: #007bff;
    color: white;
    border-color: #007bff;
  }

  .hint {
    margin-top: 0.5rem;
    font-size: 0.9rem;
    color: #666;
  }

  .hint code {
    background: #f0f0f0;
    padding: 0.2rem 0.4rem;
    border-radius: 3px;
  }
</style>
