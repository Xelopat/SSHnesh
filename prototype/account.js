export function setupAccount(api, call, passwordDialog) {
  const $ = id => document.getElementById(id);
  $('home-sync').querySelector('.sync-card').replaceWith($('native-account-template').content.cloneNode(true));

  const forget = document.createElement('button');
  forget.type = 'button';
  forget.textContent = 'Забыть ключ';
  forget.hidden = true;
  $('home-settings').append(forget);

  const formatTime = new Intl.DateTimeFormat('ru-RU', { dateStyle: 'short', timeStyle: 'short' });
  let state = {};
  let active;
  let messages = {};

  function render(next) {
    const { username, busy, loginBusy, canCancel, error, cached, unlocked, remembered, lastSynced } = next.sync;
    if (state.username !== username) {
      messages = {};
      $('account-recovery').open = false;
    }
    if (state.unlocked !== unlocked) delete messages.vault;
    state = next.sync;

    const blocked = busy || Boolean(active);
    const profileError = messages.profile || error;
    const profileStatus = canCancel ? 'Завершите вход в браузере.' : loginBusy ? 'Выполняется вход…' : 'Вход не выполнен';
    setStatus('account-profile-status', profileError || username || profileStatus, profileError);
    $('account-login').hidden = Boolean(username || canCancel);
    $('account-login').disabled = blocked;
    $('account-logout').hidden = !username;
    $('account-logout').disabled = blocked;
    $('account-cancel').hidden = !canCancel;
    $('account-cancel').disabled = Boolean(active);

    setStatus('account-vault-status', messages.vault || (unlocked ? 'Разблокировано' : cached ? 'Заблокировано' : 'На устройстве пока нет копии'), messages.vault);
    $('account-unlock').hidden = !cached || unlocked;
    $('account-unlock').disabled = blocked;
    $('account-lock').hidden = !unlocked || remembered;
    $('account-lock').disabled = blocked;
    forget.hidden = !remembered;
    forget.disabled = blocked;

    let syncStatus = 'Нет данных о последней синхронизации';
    if (active === 'sync') syncStatus = 'Синхронизация…';
    else if (messages.sync) syncStatus = messages.sync;
    else if (!username) syncStatus = 'Войдите в аккаунт для синхронизации';
    else if (lastSynced) syncStatus = `Последняя синхронизация · ${formatTime.format(lastSynced * 1000)}`;
    else if (cached && !unlocked) syncStatus = 'Разблокируйте хранилище, чтобы увидеть статус';
    setStatus('account-sync-status', syncStatus, messages.sync);
    $('account-sync').disabled = !username || blocked;
    $('account-recovery').hidden = !username;
    $('account-replace').disabled = blocked;
    $('account-recovery-status').hidden = !messages.recovery;
    setStatus('account-recovery-status', messages.recovery || '', messages.recoveryError);
  }

  function setStatus(id, text, error) {
    const element = $(id);
    if (element.textContent !== text) element.textContent = text;
    element.classList.toggle('error', Boolean(error));
  }

  function perform(section, action) {
    return async () => {
      if (active) return;
      active = section;
      delete messages[section];
      if (section === 'recovery') delete messages.recoveryError;
      render({ sync: state });
      try {
        await action(state);
        render(await api.state());
      } catch (error) {
        messages[section] = error.message;
        if (section === 'recovery') messages.recoveryError = true;
      } finally {
        active = undefined;
        render({ sync: state });
      }
    };
  }

  $('account-login').onclick = perform('profile', api.syncLogin);
  $('account-logout').onclick = perform('profile', api.syncLogout);
  $('account-cancel').onclick = perform('profile', api.syncCancel);
  $('account-lock').onclick = perform('vault', api.cloudLock);
  forget.onclick = async () => {
    try { await call('forgetDeviceKey'); }
    catch (error) { alert(error.message); }
  };
  $('account-unlock').onclick = perform('vault', async ({ remembered }) => {
    const enrollment = remembered ? undefined : {};
    const password = await passwordDialog('Разблокировать хранилище', 'Мастер-пароль', enrollment, { submit: 'Разблокировать' });
    if (password !== undefined) await call('syncTransfer', 'unlock', password, enrollment || {});
  });
  $('account-sync').onclick = perform('sync', async ({ cached, unlocked, remembered }) => {
    const enrollment = remembered ? undefined : {};
    const password = unlocked || (cached && remembered) ? '' : await passwordDialog('Синхронизация', 'Мастер-пароль', enrollment, {
      submit: 'Синхронизировать',
      hint: cached ? '' : 'Введите пароль существующего хранилища. Для нового задайте пароль от 16 символов.',
    });
    if (password !== undefined) await api.syncTransfer('push', password, enrollment || {});
  });
  $('account-replace').onclick = perform('recovery', async () => {
    const enrollment = {};
    const password = await passwordDialog('Замена облачного хранилища', 'Новый мастер-пароль', enrollment, {
      submit: 'Продолжить', minLength: 16,
    });
    if (password === undefined || !await confirmReplacement()) return;
    await call('syncTransfer', 'replace', password, { ...enrollment, confirmed: true });
    delete messages.sync;
    messages.recovery = 'Облачное хранилище заменено.';
  });

  return render;
}

async function confirmReplacement() {
  const dialog = document.createElement('dialog');
  dialog.setAttribute('aria-label', 'Заменить облачное хранилище?');
  dialog.innerHTML = `<form method="dialog">
    <h2>Заменить облачное хранилище?</h2>
    <p>В облако попадут только доступные локальные серверы и ключи. Записи из закрытого хранилища и изменения с других устройств будут исключены. Имеющиеся зашифрованные копии приложение сохранит на этом устройстве.</p>
    <div class="actions"><button value="cancel" autofocus>Отмена</button><button value="replace" class="danger">Заменить</button></div>
  </form>`;
  document.body.append(dialog);
  const answer = new Promise(resolve => dialog.onclose = () => resolve(dialog.returnValue === 'replace'));
  dialog.showModal();
  const confirmed = await answer;
  dialog.remove();
  return confirmed;
}
