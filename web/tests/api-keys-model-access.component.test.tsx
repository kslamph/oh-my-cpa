import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { ApiKeysPage } from '../src/pages/ApiKeysPage';
import { installOmcApi } from './support/omcApi';
import { renderWithOmc } from './support/render';

const KEYS = [
  { index: 0, key: 'sk-restricted-one', fingerprint: 'fp-0', usage_fingerprint: 'ufp-0', length: 17, alias: 'Cursor', alias_version: 1, allowed_models: ['claude-*', 'gpt-5-codex'], denied_models: ['gpt-5.6-*'] },
  { index: 1, key: 'sk-open-two', fingerprint: 'fp-1', usage_fingerprint: 'ufp-1', length: 11, alias_version: 0 },
];

function installKeys() {
  const api = installOmcApi();
  api.on('GET', '/management/api-keys', () => ({ keys: KEYS, total: KEYS.length }));
  api.on('GET', '/management/client-key-usage', () => ({ window: { from: 0, to: 1 }, usage: [] }));
  api.on('PUT', /^\/management\/api-keys\/\d+\/model-access$/, (request) => {
    const body = request.body as { allowed_models: string[]; denied_models: string[] };
    return { status: 'ok', index: 0, allowed_models: body.allowed_models, denied_models: body.denied_models };
  });
  return api;
}

describe('client key model access', () => {
  it('marks restricted keys in the list and leaves an unrestricted key reading as all models', async () => {
    installKeys();
    renderWithOmc(<ApiKeysPage />, { route: '/api-keys' });
    expect(await screen.findByText('Allow 2')).toBeTruthy();
    expect(screen.getByText('Deny 1')).toBeTruthy();
    expect(screen.getAllByText('All models')).toHaveLength(1);
  });

  it('edits the patterns of a key without rewriting the key, and normalizes lines on save', async () => {
    const api = installKeys();
    renderWithOmc(<ApiKeysPage />, { route: '/api-keys' });
    fireEvent.click(await screen.findByRole('button', { name: /^Edit.*Cursor/ }));

    const allowed = (await screen.findByLabelText('Allowed models')) as HTMLTextAreaElement;
    const denied = screen.getByLabelText('Denied models') as HTMLTextAreaElement;
    expect(allowed.value).toBe('claude-*\ngpt-5-codex');
    expect(denied.value).toBe('gpt-5.6-*');

    fireEvent.change(allowed, { target: { value: ' claude-* \n\n' } });
    fireEvent.change(denied, { target: { value: '' } });
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Save' }));

    await waitFor(() => expect(api.writes('/management/api-keys/0/model-access')).toHaveLength(1));
    expect(api.writes('/management/api-keys/0/model-access')[0].body).toEqual({
      expected_fingerprint: 'fp-0',
      allowed_models: ['claude-*'],
      denied_models: [],
    });
    // The secret and the name did not change, so CPA's key list is not written at all.
    expect(api.writes('/management/api-keys/0')).toHaveLength(0);
  });

  it('does not call the access endpoint when only the name changed', async () => {
    const api = installKeys();
    api.on('PUT', '/management/client-key-aliases', () => ({ status: 'ok', alias: { alias: 'Renamed', version: 2 } }));
    renderWithOmc(<ApiKeysPage />, { route: '/api-keys' });
    fireEvent.click(await screen.findByRole('button', { name: /^Edit.*Cursor/ }));
    await screen.findByLabelText('Allowed models');
    fireEvent.change(screen.getByDisplayValue('Cursor'), { target: { value: 'Renamed' } });
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(api.requests.some((request) => request.method === 'PUT')).toBe(true));
    expect(api.writes('/management/api-keys/0/model-access')).toHaveLength(0);
  });
});
