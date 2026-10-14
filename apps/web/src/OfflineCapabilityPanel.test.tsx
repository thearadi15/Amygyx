import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import OfflineCapabilityPanel from './OfflineCapabilityPanel';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('OfflineCapabilityPanel', () => {
  it('posts the selected file and clears the API token after successful analysis', async () => {
    const findingId = 'finding-123';
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        capability_id: 'risk',
        result: 'review_required',
        ruleset_version: 'risk-investment-v1',
        records_processed: 1,
        summary: { model: 'annual_expected_loss_v1' },
        indicators: [
          {
            rule_id: 'risk.investment-positive-net-benefit',
            description: 'Review the supplied scenario assumptions.',
            severity: 'low',
            evidence: { estimated_roi: 1.5 },
            finding_id: findingId,
          },
        ],
      }),
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<OfflineCapabilityPanel profileId="risk" />);
    fireEvent.change(
      screen.getByLabelText(/cyber risk & investment optimization api access token/i),
      { target: { value: 'development-token' } },
    );
    fireEvent.change(screen.getByLabelText(/optimization budget/i), {
      target: { value: '100000' },
    });
    const file = new File(['asset,control'], 'risk scenarios.csv', { type: 'text/csv' });
    fireEvent.change(screen.getByLabelText(/cyber risk & investment optimization input file/i), {
      target: { files: [file] },
    });
    fireEvent.click(screen.getByRole('button', { name: /analyze file/i }));

    expect(await screen.findByText(/review signals reported/i)).toBeInTheDocument();
    expect(screen.getByText(`Shared finding created: ${findingId}`)).toBeInTheDocument();
    const [url, request] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain(
      '/capabilities/risk/analyze?filename=risk+scenarios.csv&budget_usd=100000',
    );
    expect(request.method).toBe('POST');
    expect(request.headers).toEqual({
      Authorization: 'Bearer development-token',
      'Content-Type': 'application/octet-stream',
    });
    expect(request.body).toBe(file);
    expect(
      screen.getByLabelText(/cyber risk & investment optimization api access token/i),
    ).toHaveValue('');
  });

  it('shows API validation errors instead of displaying a success-shaped result', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        status: 422,
        json: async () => ({ detail: 'event_count must be numeric.' }),
      }),
    );

    render(<OfflineCapabilityPanel profileId="forecasting" />);
    fireEvent.change(
      screen.getByLabelText(/network event trend analysis api access token/i),
      { target: { value: 'development-token' } },
    );
    const file = new File(['bad'], 'events.csv', { type: 'text/csv' });
    fireEvent.change(screen.getByLabelText(/network event trend analysis input file/i), {
      target: { files: [file] },
    });
    fireEvent.click(screen.getByRole('button', { name: /analyze file/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent('event_count must be numeric.');
    expect(screen.queryByText(/analysis result/i)).not.toBeInTheDocument();
  });
});
