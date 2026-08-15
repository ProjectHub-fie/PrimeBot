/* Servers / overview page — the guild list is server-rendered. This script
 * just makes each guild card navigate to its settings page.
 */
document.querySelectorAll('.guild-card[data-guild]').forEach(card => {
  card.addEventListener('click', () => {
    window.location.href = `/guild/${card.dataset.guild}/prefix`;
  });
});
