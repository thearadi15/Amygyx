import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import BitcoinAnalysisPanel from './BitcoinAnalysisPanel';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const suspiciousAnalysis = {
  result: 'suspicious_indicators',
  ruleset_version: 'bitcoin-transfer-rules-v1',
  rows_processed: 21,
  indicators: [
    {
      rule_id: 'bitcoin.address-fan-out',
      description: 'A sender transferred to many distinct recipients.',
      severity: 'medium',
      evidence: {
        distinct_recipients: 10,
        threshold: 10,
      },
      finding_id: 'finding-bitcoin-123',
    },
  ],
};

describe('BitcoinAnalysisPanel', () => {
  it('requires an API token and a bounded CSV before sending', () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    render(<BitcoinAnalysisPanel />);

    fireEvent.click(screen.getByRole('button', { name: /analyze transfers/i }));
    expect(screen.getByRole('alert')).toHaveTextContent(/provide an api access token/i);

    fireEvent.change(screen.getByLabelText(/bitcoin api access token/i), {
      target: { value: 'local-token' },
    });
    fireEvent.click(screen.getByRole('button', { name: /analyze transfers/i }));
    expect(screen.getByRole('alert')).toHaveTextContent(/choose a bitcoin transfer csv/i);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('posts transfer rows and renders pseudonymized indicators', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => suspiciousAnalysis,
    });
    vi.stubGlobal('fetch', fetchMock);
    render(<BitcoinAnalysisPanel />);

    fireEvent.change(screen.getByLabelText(/bitcoin api access token/i), {
      target: { value: 'local-token' },
    });
    const csv = new File(
      [
        'transaction_id,sender_address,recipient_address,amount_btc\n' +
          `${'0'.repeat(63)}1,synthetic-sender,synthetic-recipient,0.01\n`,
      ],
      'transfers.csv',
      { type: 'text/csv' },
    );
    fireEvent.change(screen.getByLabelText(/bitcoin transfer csv file/i), {
      target: { files: [csv] },
    });
    fireEvent.click(screen.getByRole('button', { name: /analyze transfers/i }));

    await screen.findByRole('heading', { name: /transaction patterns need review/i });
    expect(fetchMock).toHaveBeenCalledWith(
      'http://127.0.0.1:8000/bitcoin/analyze',
      expect.objectContaining({
        method: 'POST',
        headers: {
          Authorization: 'Bearer local-token',
          'Content-Type': 'application/octet-stream',
        },
        body: csv,
      }),
    );
    expect(screen.getByText(/bitcoin\.address-fan-out/i)).toBeInTheDocument();
    expect(screen.getByText(/shared finding created: finding-bitcoin-123/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/bitcoin api access token/i)).toHaveValue('');
  });

  it('rejects non-CSV and oversized files without sending them', () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    render(<BitcoinAnalysisPanel />);
    fireEvent.change(screen.getByLabelText(/bitcoin api access token/i), {
      target: { value: 'local-token' },
    });

    fireEvent.change(screen.getByLabelText(/bitcoin transfer csv file/i), {
      target: { files: [new File(['data'], 'transfers.txt', { type: 'text/plain' })] },
    });
    fireEvent.click(screen.getByRole('button', { name: /analyze transfers/i }));
    expect(screen.getByRole('alert')).toHaveTextContent(/\.csv extension/i);

    fireEvent.change(screen.getByLabelText(/bitcoin transfer csv file/i), {
      target: { files: [new File([new Uint8Array(1_048_577)], 'large.csv')] },
    });
    fireEvent.click(screen.getByRole('button', { name: /analyze transfers/i }));
    expect(screen.getByRole('alert')).toHaveTextContent(/exceeds the 1 mib/i);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
