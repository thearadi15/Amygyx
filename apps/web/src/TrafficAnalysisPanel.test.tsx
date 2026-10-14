import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import TrafficAnalysisPanel from './TrafficAnalysisPanel';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const suspiciousAnalysis = {
  result: 'suspicious_indicators',
  ruleset_version: 'unidirectional-ip-rules-v1',
  rows_processed: 20,
  indicators: [
    {
      rule_id: 'network.unidirectional-port-scan',
      description: 'One source contacted many distinct destination ports.',
      severity: 'medium',
      evidence: {
        source_ip: '192.0.2.25',
        protocol: 'tcp',
        distinct_destination_ports: 20,
        threshold: 20,
      },
      finding_id: 'finding-traffic-123',
    },
  ],
};

describe('TrafficAnalysisPanel', () => {
  it('requires an API token and a bounded CSV before sending', () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    render(<TrafficAnalysisPanel />);

    fireEvent.click(screen.getByRole('button', { name: /analyze flows/i }));
    expect(screen.getByRole('alert')).toHaveTextContent(/provide an api access token/i);

    fireEvent.change(screen.getByLabelText(/traffic api access token/i), {
      target: { value: 'local-token' },
    });
    fireEvent.click(screen.getByRole('button', { name: /analyze flows/i }));
    expect(screen.getByRole('alert')).toHaveTextContent(/choose a flow csv/i);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('posts one-way flow records and renders aggregate indicators', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => suspiciousAnalysis,
    });
    vi.stubGlobal('fetch', fetchMock);
    render(<TrafficAnalysisPanel />);

    fireEvent.change(screen.getByLabelText(/traffic api access token/i), {
      target: { value: 'local-token' },
    });
    const csv = new File(
      [
        'source_ip,destination_ip,destination_port,protocol,bytes,packets\n' +
          '192.0.2.25,198.51.100.10,22,tcp,60,1\n',
      ],
      'flows.csv',
      { type: 'text/csv' },
    );
    fireEvent.change(screen.getByLabelText(/unidirectional flow csv file/i), {
      target: { files: [csv] },
    });
    fireEvent.click(screen.getByRole('button', { name: /analyze flows/i }));

    await screen.findByRole('heading', { name: /traffic patterns need review/i });
    expect(fetchMock).toHaveBeenCalledWith(
      'http://127.0.0.1:8000/traffic/analyze',
      expect.objectContaining({
        method: 'POST',
        headers: {
          Authorization: 'Bearer local-token',
          'Content-Type': 'application/octet-stream',
        },
        body: csv,
      }),
    );
    expect(screen.getByText(/network\.unidirectional-port-scan/i)).toBeInTheDocument();
    expect(screen.getByText(/shared finding created: finding-traffic-123/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/traffic api access token/i)).toHaveValue('');
  });

  it('rejects non-CSV and oversized files without sending them', () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    render(<TrafficAnalysisPanel />);
    fireEvent.change(screen.getByLabelText(/traffic api access token/i), {
      target: { value: 'local-token' },
    });

    fireEvent.change(screen.getByLabelText(/unidirectional flow csv file/i), {
      target: { files: [new File(['data'], 'flows.txt', { type: 'text/plain' })] },
    });
    fireEvent.click(screen.getByRole('button', { name: /analyze flows/i }));
    expect(screen.getByRole('alert')).toHaveTextContent(/\.csv extension/i);

    fireEvent.change(screen.getByLabelText(/unidirectional flow csv file/i), {
      target: { files: [new File([new Uint8Array(1_048_577)], 'large.csv')] },
    });
    fireEvent.click(screen.getByRole('button', { name: /analyze flows/i }));
    expect(screen.getByRole('alert')).toHaveTextContent(/exceeds the 1 mib/i);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
