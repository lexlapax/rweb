'use strict';
document.getElementById('b4').addEventListener('click', () => {});
document.getElementById('o7').onclick = () => document.getElementById('d7').showModal();
document.getElementById('c7').onclick = () => document.getElementById('d7').close();
const rows = document.getElementById('rows');
for (let i = 1; i <= 30; i++) { const d = document.createElement('div'); d.className = 'ln'; d.textContent = `line ${i}: the quick brown fox jumps over the lazy dog`; rows.append(d); }
rows.addEventListener('click', () => {});
document.getElementById('o8').onclick = () => document.getElementById('fs').showModal();
document.getElementById('c8').onclick = () => document.getElementById('fs').close();
// the same global rule the real page has
document.documentElement.style.overscrollBehavior = 'none'; document.body.style.overscrollBehavior = 'none';
