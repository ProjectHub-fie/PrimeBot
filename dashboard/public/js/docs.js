/**
 * Command documentation page: live search + filtering.
 * Filters .doc-cmd cards by their data-search haystack; hides empty category
 * sections; shows the matching command count; '/' focuses the search box.
 */
(function () {
    const input = document.getElementById('docs-search');
    if (!input) return;

    const cards = Array.from(document.querySelectorAll('.doc-cmd'));
    const sections = Array.from(document.querySelectorAll('.doc-cat'));
    const countEl = document.getElementById('docs-count');
    const emptyEl = document.getElementById('docs-empty');

    function apply() {
        const q = input.value.trim().toLowerCase();
        let shown = 0;
        for (const card of cards) {
            const match = !q || (card.dataset.search || '').includes(q);
            card.classList.toggle('doc-hidden', !match);
            if (match) shown++;
        }
        for (const section of sections) {
            section.classList.toggle('doc-hidden', !section.querySelector('.doc-cmd:not(.doc-hidden)'));
        }
        if (countEl) countEl.textContent = `${shown} command${shown === 1 ? '' : 's'}`;
        if (emptyEl) emptyEl.classList.toggle('doc-hidden', shown !== 0);
    }

    input.addEventListener('input', apply);

    document.addEventListener('keydown', (e) => {
        if (e.key === '/' && document.activeElement !== input && !/^(input|textarea|select)$/i.test(document.activeElement?.tagName || '')) {
            e.preventDefault();
            input.focus();
        }
    });
})();
