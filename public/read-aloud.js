(() => {
  const synth = globalThis.speechSynthesis;
  const supported = !!synth && typeof globalThis.SpeechSynthesisUtterance === 'function';
  let active = false, paused = false, generation = 0, current;
  let message = '';
  const element = id => document.getElementById(id);
  // Only device-local English voices are used. No remote voice fallback.
  const voice = () => supported ? synth.getVoices().find(v => v.localService && /^en(?:-|$)/i.test(v.lang)) : null;
  function refresh() {
    const available = !!voice();
    document.querySelectorAll('[data-read-aloud]').forEach(button => {button.disabled = !available;});
    const pause = element('speech-pause'), stopButton = element('speech-stop'), rate = element('speech-rate');
    if (pause) {pause.disabled = !active; pause.textContent = paused ? 'Resume' : 'Pause';}
    if (stopButton) stopButton.disabled = !active;
    if (rate) rate.disabled = active;
    const status = element('speech-status');
    if (status) status.textContent = message || (!supported ?
      'Read aloud is not supported in this browser. You can still read and accept the text below.' :
      !available ? 'No on-device English voice is available yet. Add an English speech voice in your device settings, then reopen this page. You can still read the text below.' :
      'Ready. Choose what you want to hear.');
  }
  function stop() {
    generation++;
    if (supported && active) synth.cancel();
    active = false; paused = false; current = null; message = '';
    refresh();
  }
  function read(target) {
    const selectedVoice = voice();
    if (!selectedVoice || !['privacy-copy', 'terms-copy', 'all-disclosures'].includes(target)) return;
    const root = element(target);
    if (!root) return;
    // Read only the public disclosure copy. Never read form fields or account data.
    const text = [...root.querySelectorAll('h2,h3,p')].map(node => node.textContent.trim()).filter(Boolean);
    const chunks = text.flatMap(paragraph => {
      const words = paragraph.split(/\s+/), result = []; let chunk = '';
      for (const word of words) {
        if ((chunk + ' ' + word).length > 240 && chunk) {result.push(chunk); chunk = '';}
        chunk += (chunk ? ' ' : '') + word;
      }
      if (chunk) result.push(chunk);
      return result;
    });
    if (!chunks.length) return;
    stop();
    const token = generation;
    const requestedRate = Number(element('speech-rate')?.value || 1);
    const rate = [0.8, 1, 1.2].includes(requestedRate) ? requestedRate : 1;
    active = true; paused = false; message = 'Reading aloud. You can pause or stop at any time.';
    function next() {
      if (token !== generation) return;
      const chunk = chunks.shift();
      if (!chunk) {active = false; current = null; message = 'Finished reading. Check each box yourself and sign when you are ready.';refresh();return;}
      current = new SpeechSynthesisUtterance(chunk);
      current.voice = selectedVoice; current.lang = selectedVoice.lang; current.rate = rate;
      current.onend = next;
      current.onerror = () => {
        if (token !== generation) return;
        stop(); message = 'Reading stopped. Try again, or read the text below.'; refresh();
      };
      try {synth.speak(current);} catch {current.onerror();}
    }
    synth.resume(); next(); refresh();
  }
  document.addEventListener('click', event => {
    const readButton = event.target.closest('[data-read-aloud]');
    if (readButton && !readButton.disabled) {read(readButton.dataset.readAloud);return;}
    if (event.target.closest('#speech-stop')) {stop();message = 'Reading stopped.';refresh();return;}
    if (event.target.closest('#speech-pause') && active) {
      paused = !paused;
      if (paused) synth.pause(); else synth.resume();
      message = paused ? 'Reading paused. Choose Resume to continue.' : 'Reading aloud.';
      refresh();
    }
  });
  if (supported) synth.addEventListener('voiceschanged', refresh);
  globalThis.addEventListener('pagehide', stop);
  globalThis.CyberOneSpeech = {stop, refresh};
})();
