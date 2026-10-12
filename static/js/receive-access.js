(function () {
    const form = document.getElementById('receive-access-form');
    if (!form) return;

    const checkbox = document.getElementById('access-creator-only');
    const emails = document.getElementById('access-emails');
    const emailField = document.getElementById('access-reader-emails');
    const button = form.querySelector('button[type="submit"]');
    const status = document.getElementById('access-status');
    const forced = checkbox.dataset.forced === 'true';

    function updateFields() {
        emailField.classList.toggle('hidden', !checkbox.checked);
        emails.disabled = !checkbox.checked;
    }

    form.addEventListener('input', function () {
        form.dataset.dirty = 'true';
        status.textContent = '';
    });
    checkbox.addEventListener('change', updateFields);
    form.addEventListener('submit', async function (event) {
        event.preventDefault();
        if (form.dataset.saving === 'true') return;

        const payload = {
            creator_only: checkbox.checked,
            allowed_reader_emails: checkbox.checked
                ? emails.value.split(/[\s,;]+/).filter(Boolean)
                : [],
        };
        form.dataset.saving = 'true';
        button.disabled = true;
        checkbox.disabled = true;
        emails.disabled = true;
        status.classList.remove('text-red-400');
        status.textContent = gettext('Saving…');
        try {
            const response = await fetch(form.dataset.url, {
                method: 'PATCH',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': form.querySelector('[name=csrfmiddlewaretoken]').value,
                },
                body: JSON.stringify(payload),
            });
            let data;
            try {
                data = await response.json();
            } catch (error) {
                throw new Error(gettext('Could not update access.'));
            }
            if (!response.ok) throw new Error(data.error || gettext('Could not update access.'));
            checkbox.checked = data.creator_only;
            emails.value = data.allowed_reader_emails.join('\n');
            form.dataset.dirty = 'false';
            status.textContent = gettext('Access updated.');
        } catch (error) {
            status.classList.add('text-red-400');
            status.textContent = error.message || gettext('Could not update access.');
        } finally {
            form.dataset.saving = 'false';
            button.disabled = false;
            checkbox.disabled = forced;
            updateFields();
        }
    });
    updateFields();
})();