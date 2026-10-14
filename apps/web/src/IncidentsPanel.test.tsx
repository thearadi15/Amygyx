import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import IncidentsPanel from './IncidentsPanel';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const findingRows = [
  {
    id: 'finding-email-1',
    title: 'Email contains suspicious indicators',
    severity: 'medium',
    source_type: 'email',
  },
  {
    id: 'finding-bitcoin-1',
    title: 'Bitcoin transfer fan-out',
    severity: 'medium',
    source_type: 'bitcoin_transaction',
  },
];

function incident(overrides: Record<string, unknown> = {}) {
  return {
    id: 'incident-1',
    title: 'Suspicious activity investigation',
    summary: 'Correlate related signals.',
    severity: 'high',
    status: 'new',
    owner_id: null,
    finding_ids: [],
    created_at: '2026-10-13T12:00:00Z',
    updated_at: '2026-10-13T12:00:00Z',
    ...overrides,
  };
}

describe('IncidentsPanel', () => {
  it('requires a token and loads incidents and findings for the authenticated tenant', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    render(<IncidentsPanel />);

    fireEvent.click(screen.getByRole('button', { name: /load incidents and findings/i }));
    expect(screen.getByRole('alert')).toHaveTextContent(/provide an api access token/i);
    expect(fetchMock).not.toHaveBeenCalled();

    fetchMock
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => [] })
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => findingRows });
    fireEvent.change(screen.getByLabelText(/incidents api access token/i), {
      target: { value: 'local-token' },
    });
    fireEvent.click(screen.getByRole('button', { name: /load incidents and findings/i }));

    expect(await screen.findByText(/no incidents are recorded/i)).toBeInTheDocument();
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      'http://127.0.0.1:8000/incidents?limit=100',
      expect.objectContaining({ headers: { Authorization: 'Bearer local-token' } }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      'http://127.0.0.1:8000/findings?limit=100',
      expect.objectContaining({ headers: { Authorization: 'Bearer local-token' } }),
    );
    expect(screen.getByLabelText(/incidents api access token/i)).toHaveValue('local-token');
    fireEvent.click(screen.getByRole('button', { name: /clear token/i }));
    expect(screen.getByLabelText(/incidents api access token/i)).toHaveValue('');
  });

  it('creates an incident with selected findings then links and transitions it using supported methods', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    render(<IncidentsPanel />);
    fetchMock
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => [] })
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => findingRows });
    fireEvent.change(screen.getByLabelText(/incidents api access token/i), {
      target: { value: 'local-token' },
    });
    fireEvent.click(screen.getByRole('button', { name: /load incidents and findings/i }));
    await screen.findByRole('heading', { name: /create incident/i });

    fireEvent.change(screen.getByLabelText(/incident title/i), {
      target: { value: '  Combined signals  ' },
    });
    fireEvent.change(screen.getByLabelText(/incident summary/i), {
      target: { value: 'Review findings together.' },
    });
    fireEvent.click(screen.getByLabelText(/email contains suspicious indicators/i));
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 201,
      json: async () =>
        incident({ title: 'Combined signals', finding_ids: ['finding-email-1'] }),
    });
    fireEvent.click(screen.getByRole('button', { name: /create incident/i }));

    await screen.findByText(/incident created: incident-1/i);
    const createCall = fetchMock.mock.calls[2];
    expect(createCall[0]).toBe('http://127.0.0.1:8000/incidents');
    expect(createCall[1].method).toBe('POST');
    expect(JSON.parse(createCall[1].body)).toEqual({
      title: 'Combined signals',
      summary: 'Review findings together.',
      severity: 'medium',
      finding_ids: ['finding-email-1'],
    });

    fireEvent.change(screen.getByLabelText(/finding to link to combined signals/i), {
      target: { value: 'finding-bitcoin-1' },
    });
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => incident({ finding_ids: ['finding-email-1', 'finding-bitcoin-1'] }),
    });
    fireEvent.click(screen.getByRole('button', { name: /link finding/i }));
    await screen.findByText(/finding linked to incident/i);
    expect(fetchMock.mock.calls[3][0]).toBe(
      'http://127.0.0.1:8000/incidents/incident-1/findings',
    );
    expect(fetchMock.mock.calls[3][1].method).toBe('POST');
    expect(JSON.parse(fetchMock.mock.calls[3][1].body)).toEqual({
      finding_id: 'finding-bitcoin-1',
    });

    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => incident({
        status: 'investigating',
        finding_ids: ['finding-email-1', 'finding-bitcoin-1'],
      }),
    });
    fireEvent.click(screen.getByRole('button', { name: /^investigating$/i }));
    await screen.findByText(/incident status changed to investigating/i);
    expect(fetchMock.mock.calls[4][0]).toBe(
      'http://127.0.0.1:8000/incidents/incident-1/status',
    );
    expect(fetchMock.mock.calls[4][1].method).toBe('PATCH');
    expect(JSON.parse(fetchMock.mock.calls[4][1].body)).toEqual({ status: 'investigating' });
    expect(screen.queryByRole('button', { name: /^closed$/i })).not.toBeInTheDocument();
  });

  it('surfaces API conflict and keeps the incident at its current status', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    fetchMock
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => [incident()],
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => findingRows,
      });
    render(<IncidentsPanel />);
    fireEvent.change(screen.getByLabelText(/incidents api access token/i), {
      target: { value: 'local-token' },
    });
    fireEvent.click(screen.getByRole('button', { name: /load incidents and findings/i }));
    await screen.findByRole('button', { name: /^investigating$/i });

    expect(screen.queryByRole('button', { name: /^closed$/i })).not.toBeInTheDocument();
    fetchMock.mockResolvedValueOnce({
      ok: false,
      status: 409,
      json: async () => ({ detail: "Cannot transition incident from 'new' to 'closed'." }),
    });
    fireEvent.click(screen.getByRole('button', { name: /^investigating$/i }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/cannot transition incident/i);
    expect(screen.getByRole('button', { name: /^investigating$/i })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^closed$/i })).not.toBeInTheDocument();
  });

  it('shows no incidents and gracefully reports malformed API responses', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => [] })
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => findingRows })
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => [{ id: 'invalid' }] })
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => findingRows });
    vi.stubGlobal('fetch', fetchMock);
    render(<IncidentsPanel />);
    fireEvent.change(screen.getByLabelText(/incidents api access token/i), {
      target: { value: 'local-token' },
    });
    fireEvent.click(screen.getByRole('button', { name: /load incidents and findings/i }));
    expect(await screen.findByText(/no incidents are recorded/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /load incidents and findings/i }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/unexpected incident workflow response/i);
  });
});
