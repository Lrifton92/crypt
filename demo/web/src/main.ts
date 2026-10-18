import "@fontsource/press-start-2p";
import "@fontsource/vt323";
import "./style.css";
import { loadEngine } from "./engine";
import { initFx } from "./fx";
import { title } from "./screens";

initFx();

loadEngine()
  .then(() => title())
  .catch((error: unknown) => {
    console.error(error);
    const boot = document.getElementById("boot");
    if (!boot) return;
    boot.classList.add("failed");
    boot.innerHTML =
      '<h1 class="boot-title">THE CRYPT IS SEALED</h1>' +
      "<p>Your browser could not load the crypt engine (WebAssembly). Try a recent Chrome, Firefox or Safari.</p>" +
      '<p><a href="https://github.com/Lrifton92/crypt">The source is on GitHub.</a></p>';
  });
