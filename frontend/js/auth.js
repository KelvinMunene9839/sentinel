document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('login-form');
  const errBox = document.getElementById('login-error');
  const btn = document.getElementById('login-btn');

  if (!form) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errBox.style.display = 'none';
    btn.disabled = true;
    btn.textContent = 'Signing in…';

    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;

    try {
      await window.SentinelAPI.login(username, password);
      window.showToast('Signed in');
      window.location.href = '/dashboard.html';
    } catch (err) {
      errBox.textContent = err.message || 'Authentication failed';
      errBox.style.display = 'block';
    } finally {
      btn.disabled = false;
      btn.textContent = 'Sign in';
    }
  });
});
