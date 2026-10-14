import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import FindingsPanel from './FindingsPanel';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const findings = [
  {
    id: 'finding-bitcoin-1',
    source_type: 'bitcoin_transaction',
    title: 'A sender transferred to many recipients',
    summary: 'This pattern can reflect batching or other expected activity.',
    severity: 'medium',
    confidence: 0.5,
    business_impact: 'moderate',
    status: 'open',
    rule_id: 'bitcoin.address-fan-out',
    detector_version: 'bitcoin-transfer-rules-v1',
    evidence: { distinct_recipients: 10, threshold: 10 },
    created_at: '2026-10-13T12:00:00Z',
    updated_at: '2026-10-13T12:00:00Z',
  },
  {
    id: 'finding-email-1',
    source_type: 'email',
    title: 'Email contains suspicious indicators',
    summary: 'Indicators are not confirmation of malicious activity.',
    severity: 'medium',
    confidence: 0.5,
    business_impact: 'moderate',
    status: 'investigating',
    rule_id: 'email.ip-literal-link',
    detector_version: 'email-rules-v1',
    evidence: null,
    created_at: '2026-10-13T11:00:00Z',
    updated_at: '2026-10-13T11:00:00Z',
  },
];

describe('FindingsPanel', () => {
  it('requires an API token and sends a tenant-scoped list request', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    render(<FindingsPanel />);

    fireEvent.click(screen.getByRole('button', { name: /load tenant findings/i }));
    expect(screen.getByRole('alert')).toHaveTextContent(/provide an api access token/i);
    expect(fetchMock).not.toHaveBeenCalled();

    fireEvent.change(screen.getByLabelText(/findings api access token/i), {
      target: { value: 'local-token' },
    });
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => findings,
    });
    fireEvent.click(screen.getByRole('button', { name: /load tenant findings/i }));

    expect(await screen.findByRole('heading', { name: /shared findings/i })).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      'http://127.0.0.1:8000/findings?limit=100',
      expect.objectContaining({
        headers: { Authorization: 'Bearer local-token' },
      }),
    );
    expect(screen.getByText(/bitcoin transaction/i)).toBeInTheDocument();
    expect(screen.getByText(/email contains suspicious indicators/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/findings api access token/i)).toHaveValue('');
    expect(screen.getByText(/2 shown · newest first · maximum 100/i)).toBeInTheDocument();
  });

  it('shows an explicit empty state for a tenant without findings', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => [],
      }),
    );
    render(<FindingsPanel />);
    fireEvent.change(screen.getByLabelText(/findings api access token/i), {
      target: { value: 'local-token' },
    });
    fireEvent.click(screen.getByRole('button', { name: /load tenant findings/i }));

    expect(await screen.findByText(/no findings are recorded for this tenant yet/i)).toBeInTheDocument();
  });

  it('surfaces API errors and malformed responses', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: async () => ({ detail: 'Invalid or expired authentication token.' }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => [{ id: 'invalid' }],
      });
    vi.stubGlobal('fetch', fetchMock);
    render(<FindingsPanel />);
    const tokenInput = screen.getByLabelText(/findings api access token/i);

    fireEvent.change(tokenInput, { target: { value: 'bad-token' } });
    fireEvent.click(screen.getByRole('button', { name: /load tenant findings/i }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/invalid or expired/i);

    fireEvent.change(tokenInput, { target: { value: 'local-token' } });
    fireEvent.click(screen.getByRole('button', { name: /load tenant findings/i }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/unexpected findings response/i);
  });

  it('keeps evidence collapsed until an analyst explicitly opens it', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => findings,
      }),
    );
    render(<FindingsPanel />);
    fireEvent.change(screen.getByLabelText(/findings api access token/i), {
      target: { value: 'local-token' },
    });
    fireEvent.click(screen.getByRole('button', { name: /load tenant findings/i }));

    const evidence = await screen.findByText('Evidence');
    const details = evidence.closest('details');
    expect(details).not.toHaveAttribute('open');
    fireEvent.click(evidence);
    expect(within(details as HTMLElement).getByText(/distinct_recipients/)).toBeInTheDocument();
  });
});
